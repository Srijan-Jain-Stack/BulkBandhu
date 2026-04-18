"""
Group Buy Pooling Platform — FastAPI Backend
============================================
Covers:
  1. JWT Authentication (access + refresh tokens)
  2. Pool & Commitment CRUD
  3. Pooling logic (MOQ → Success transition)
  4. WebSocket real-time updates (Redis pub/sub fan-out)
  5. Payment / Escrow via Stripe (authorize on commit, capture on success, release on fail)
"""

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import stripe
import redis.asyncio as aioredis
from fastapi import (
    Depends, FastAPI, HTTPException, WebSocket,
    WebSocketDisconnect, status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
DATABASE_URL   = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:1234@localhost/groupbuy")
REDIS_URL      = os.getenv("REDIS_URL", "redis://localhost:6379")
SECRET_KEY     = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM      = "HS256"
ACCESS_TTL     = int(os.getenv("ACCESS_TOKEN_TTL_MINUTES", "15"))
REFRESH_TTL    = int(os.getenv("REFRESH_TOKEN_TTL_DAYS", "30"))
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")

logger = logging.getLogger("groupbuy")

# ─────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────
engine = create_async_engine(DATABASE_URL, pool_pre_ping=True, pool_size=10)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
from typing import AsyncGenerator

async def get_db() -> AsyncGenerator[AsyncSession, None]:

 async with AsyncSessionLocal() as session:
        yield session

# ─────────────────────────────────────────
# REDIS
# ─────────────────────────────────────────
redis_client: aioredis.Redis = None

async def get_redis() -> aioredis.Redis:
    return redis_client

# ─────────────────────────────────────────
# SECURITY
# ─────────────────────────────────────────
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer_scheme = HTTPBearer()

def hash_password(plain: str) -> str: 
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TTL)
    return jwt.encode({"sub": user_id, "exp": expire, "type": "access"}, SECRET_KEY, ALGORITHM)

def create_refresh_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TTL)
    return jwt.encode({"sub": user_id, "exp": expire, "type": "refresh"}, SECRET_KEY, ALGORITHM)

async def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
):
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id: str = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    result = await db.execute(text("SELECT id, email, display_name FROM users WHERE id = :id"), {"id": user_id})
    user = result.mappings().first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ─────────────────────────────────────────
# PYDANTIC SCHEMAS
# ─────────────────────────────────────────
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    display_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenRefresh(BaseModel):
    refresh_token: str

class PoolCreate(BaseModel):
    title: str
    description: Optional[str] = None
    image_url: Optional[str] = None
    product_url: Optional[str] = None
    moq: int
    unit_price: float
    currency: str = "USD"
    deadline: datetime

class CommitmentCreate(BaseModel):
    quantity: int = 1
    payment_method_id: str   # Stripe PaymentMethod ID from frontend

# ─────────────────────────────────────────
# POOLING LOGIC
# ─────────────────────────────────────────
class PoolingService:
    """
    Core business logic for MOQ transitions.
    Called after any commitment change. The DB trigger handles the counter
    and auto-transitions status; this layer handles side-effects.
    """

    @staticmethod
    async def handle_post_commit(pool_id: str, db: AsyncSession, redis: aioredis.Redis):
        """
        After a new commitment is written, reload pool state and react:
        - If just transitioned to 'success' → capture all escrowed payments
        - Broadcast real-time update to WebSocket subscribers
        """
        result = await db.execute(
            text("SELECT id, status, committed_qty, moq, success_at FROM pools WHERE id = :id"),
            {"id": pool_id},
        )
        pool = result.mappings().first()
        if not pool:
            return

        # Broadcast progress to all WebSocket listeners on this pool
        await PoolingService.broadcast(redis, pool_id, {
            "event": "pool_update",
            "pool_id": pool_id,
            "committed_qty": pool["committed_qty"],
            "moq": pool["moq"],
            "status": pool["status"],
            "progress_pct": min(100, round(pool["committed_qty"] / pool["moq"] * 100, 1)),
        })

        # MOQ just reached → capture Stripe payments
        if pool["status"] == "success" and pool["success_at"]:
            await PoolingService.capture_all_payments(pool_id, db)
            await PoolingService.broadcast(redis, pool_id, {
                "event": "pool_success",
                "pool_id": pool_id,
                "message": "🎉 MOQ reached! Payments are being captured.",
            })

    @staticmethod
    async def capture_all_payments(pool_id: str, db: AsyncSession):
        """Capture every pending Stripe PaymentIntent for this pool."""
        result = await db.execute(
            text("""
                SELECT id, stripe_payment_intent_id
                FROM commitments
                WHERE pool_id = :pid AND status = 'pending'
                  AND stripe_payment_intent_id IS NOT NULL
            """),
            {"pid": pool_id},
        )
        commitments = result.mappings().all()

        for c in commitments:
            try:
                stripe.PaymentIntent.capture(c["stripe_payment_intent_id"])
                await db.execute(
                    text("""
                        UPDATE commitments
                        SET status = 'captured', updated_at = NOW()
                        WHERE id = :id
                    """),
                    {"id": c["id"]},
                )
            except stripe.error.StripeError as e:
                logger.error("Stripe capture failed for commitment %s: %s", c["id"], e)

        await db.commit()

    @staticmethod
    async def release_all_payments(pool_id: str, db: AsyncSession, redis: aioredis.Redis):
        """Cancel all payment authorisations (pool failed / cancelled)."""
        result = await db.execute(
            text("""
                SELECT id, stripe_payment_intent_id
                FROM commitments
                WHERE pool_id = :pid AND status = 'pending'
                  AND stripe_payment_intent_id IS NOT NULL
            """),
            {"pid": pool_id},
        )
        commitments = result.mappings().all()

        for c in commitments:
            try:
                stripe.PaymentIntent.cancel(c["stripe_payment_intent_id"])
                await db.execute(
                    text("""
                        UPDATE commitments
                        SET status = 'refunded', updated_at = NOW()
                        WHERE id = :id
                    """),
                    {"id": c["id"]},
                )
            except stripe.error.StripeError as e:
                logger.error("Stripe cancel failed for commitment %s: %s", c["id"], e)

        await db.execute(
            text("UPDATE pools SET status = 'failed', updated_at = NOW() WHERE id = :id"),
            {"id": pool_id},
        )
        await db.commit()

        await PoolingService.broadcast(redis, pool_id, {
            "event": "pool_failed",
            "pool_id": pool_id,
            "message": "Pool deadline passed without reaching MOQ. Payments released.",
        })

    @staticmethod
    async def broadcast(redis: aioredis.Redis, pool_id: str, payload: dict):
        channel = f"pool:{pool_id}"
        await redis.publish(channel, json.dumps(payload))

# ─────────────────────────────────────────
# WEBSOCKET CONNECTION MANAGER
# ─────────────────────────────────────────
class ConnectionManager:
    """
    Maintains active WebSocket connections per pool.
    A background task subscribes to Redis pub/sub and fans out to all
    connected clients — works across multiple server instances.
    """

    def __init__(self):
        # pool_id → set of WebSocket connections
        self._connections: dict[str, set[WebSocket]] = {}

    async def connect(self, ws: WebSocket, pool_id: str):
        await ws.accept()
        self._connections.setdefault(pool_id, set()).add(ws)

    def disconnect(self, ws: WebSocket, pool_id: str):
        if pool_id in self._connections:
            self._connections[pool_id].discard(ws)
            if not self._connections[pool_id]:
                del self._connections[pool_id]

    async def send_to_pool(self, pool_id: str, message: str):
        dead = set()
        for ws in self._connections.get(pool_id, set()):
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.disconnect(ws, pool_id)

manager = ConnectionManager()

async def redis_subscriber(app_redis: aioredis.Redis):
    """Background task: subscribe to all pool channels and fan-out to WS clients."""
    pubsub = app_redis.pubsub()
    await pubsub.psubscribe("pool:*")
    async for message in pubsub.listen():
        if message["type"] == "pmessage":
            channel: str = message["channel"].decode()   # "pool:<uuid>"
            pool_id = channel.split(":", 1)[1]
            data = message["data"].decode()
            await manager.send_to_pool(pool_id, data)

# ─────────────────────────────────────────
# APP LIFECYCLE
# ─────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=False)
    # Start the Redis subscriber background task
    task = asyncio.create_task(redis_subscriber(redis_client))
    yield
    task.cancel()
    await redis_client.aclose()

app = FastAPI(title="Group Buy API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────
# ROUTES — AUTH
# ─────────────────────────────────────────
@app.post("/auth/register", status_code=201)
async def register(body: UserRegister, db: AsyncSession = Depends(get_db)):
    exists = await db.execute(text("SELECT id FROM users WHERE email = :e"), {"e": body.email})
    if exists.first():
        raise HTTPException(400, "Email already registered")

    result = await db.execute(
        text("""
            INSERT INTO users (email, password_hash, display_name)
            VALUES (:email, :pw, :name) RETURNING id
        """),
        {"email": body.email, "pw": hash_password(body.password), "name": body.display_name},
    )
    user_id = str(result.scalar())
    await db.commit()
    return {"user_id": user_id, "access_token": create_access_token(user_id), "refresh_token": create_refresh_token(user_id)}


@app.post("/auth/login")
async def login(body: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        text("SELECT id, password_hash FROM users WHERE email = :e"), {"e": body.email}
    )
    user = result.mappings().first()
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")

    uid = str(user["id"])
    return {"access_token": create_access_token(uid), "refresh_token": create_refresh_token(uid)}


@app.post("/auth/refresh")
async def refresh_token(body: TokenRefresh, db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt.decode(body.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(401, "Invalid token type")
        user_id = payload["sub"]
    except JWTError:
        raise HTTPException(401, "Invalid refresh token")

    return {"access_token": create_access_token(user_id)}

# ─────────────────────────────────────────
# ROUTES — POOLS
# ─────────────────────────────────────────
@app.post("/pools", status_code=201)
async def create_pool(
    body: PoolCreate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if body.deadline <= datetime.now(timezone.utc):
        raise HTTPException(400, "Deadline must be in the future")

    result = await db.execute(
        text("""
            INSERT INTO pools (creator_id, title, description, image_url, product_url,
                               moq, unit_price, currency, deadline)
            VALUES (:creator, :title, :desc, :img, :url, :moq, :price, :cur, :deadline)
            RETURNING id
        """),
        {
            "creator": str(current_user["id"]),
            "title": body.title, "desc": body.description, "img": body.image_url,
            "url": body.product_url, "moq": body.moq, "price": body.unit_price,
            "cur": body.currency, "deadline": body.deadline,
        },
    )
    pool_id = str(result.scalar())
    await db.commit()
    return {"pool_id": pool_id}


@app.get("/pools/{pool_id}")
async def get_pool(pool_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        text("""
            SELECT p.*, u.display_name AS creator_name
            FROM pools p JOIN users u ON p.creator_id = u.id
            WHERE p.id = :id
        """),
        {"id": pool_id},
    )
    pool = result.mappings().first()
    if not pool:
        raise HTTPException(404, "Pool not found")
    return dict(pool)

# ─────────────────────────────────────────
# ROUTES — COMMITMENTS  (with Stripe escrow)
# ─────────────────────────────────────────
@app.post("/pools/{pool_id}/commit", status_code=201)
async def commit_to_pool(
    pool_id: str,
    body: CommitmentCreate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
):
    # 1. Validate pool is open
    pool_res = await db.execute(
        text("SELECT id, status, unit_price, currency, moq FROM pools WHERE id = :id FOR UPDATE"),
        {"id": pool_id},
    )
    pool = pool_res.mappings().first()
    if not pool:
        raise HTTPException(404, "Pool not found")
    if pool["status"] != "open":
        raise HTTPException(400, f"Pool is not open (status: {pool['status']})")

    # 2. Prevent duplicate commitment
    existing = await db.execute(
        text("SELECT id FROM commitments WHERE pool_id = :pid AND user_id = :uid"),
        {"pid": pool_id, "uid": str(current_user["id"])},
    )
    if existing.first():
        raise HTTPException(409, "You have already committed to this pool")

    # 3. Create Stripe PaymentIntent (manual capture = escrow)
    amount_cents = int(pool["unit_price"] * body.quantity * 100)
    try:
        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency=pool["currency"].lower(),
            payment_method=body.payment_method_id,
            customer=(await _get_or_create_stripe_customer(current_user, db)),
            capture_method="manual",   # ← hold, don't charge yet
            confirm=True,
            metadata={"pool_id": pool_id, "user_id": str(current_user["id"])},
        )
    except stripe.error.CardError as e:
        raise HTTPException(402, str(e.user_message))
    except stripe.error.StripeError as e:
        raise HTTPException(502, f"Payment provider error: {e}")

    # 4. Write commitment row
    await db.execute(
        text("""
            INSERT INTO commitments
                (pool_id, user_id, quantity, unit_price_snapshot, stripe_payment_intent_id, status)
            VALUES (:pid, :uid, :qty, :price, :intent_id, 'pending')
        """),
        {
            "pid": pool_id, "uid": str(current_user["id"]),
            "qty": body.quantity, "price": pool["unit_price"],
            "intent_id": intent.id,
        },
    )
    await db.commit()

    # 5. Handle side-effects (MOQ check, broadcast)
    await PoolingService.handle_post_commit(pool_id, db, redis)

    return {"status": "committed", "payment_intent_id": intent.id}


async def _get_or_create_stripe_customer(user, db: AsyncSession) -> str:
    """Retrieve or create a Stripe Customer for the user."""
    result = await db.execute(
        text("SELECT stripe_customer_id FROM users WHERE id = :id"), {"id": str(user["id"])}
    )
    row = result.mappings().first()
    if row and row["stripe_customer_id"]:
        return row["stripe_customer_id"]

    customer = stripe.Customer.create(email=user["email"])
    await db.execute(
        text("UPDATE users SET stripe_customer_id = :cid WHERE id = :id"),
        {"cid": customer.id, "id": str(user["id"])},
    )
    await db.commit()
    return customer.id

# ─────────────────────────────────────────
# ROUTES — POOL LIFECYCLE (admin / creator)
# ─────────────────────────────────────────
@app.post("/pools/{pool_id}/cancel")
async def cancel_pool(
    pool_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
):
    result = await db.execute(
        text("SELECT creator_id, status FROM pools WHERE id = :id"), {"id": pool_id}
    )
    pool = result.mappings().first()
    if not pool:
        raise HTTPException(404, "Pool not found")
    if str(pool["creator_id"]) != str(current_user["id"]):
        raise HTTPException(403, "Only the creator can cancel this pool")
    if pool["status"] not in ("open",):
        raise HTTPException(400, "Pool cannot be cancelled in its current state")

    await PoolingService.release_all_payments(pool_id, db, redis)
    await db.execute(
        text("UPDATE pools SET status = 'cancelled' WHERE id = :id"), {"id": pool_id}
    )
    await db.commit()
    return {"message": "Pool cancelled, payments released"}

# ─────────────────────────────────────────
# WEBSOCKET ENDPOINT
# ─────────────────────────────────────────
@app.websocket("/ws/pools/{pool_id}")
async def pool_websocket(
    ws: WebSocket,
    pool_id: str,
    token: Optional[str] = None,   # ?token=<jwt> as query param
    db: AsyncSession = Depends(get_db),
):
    # Optional auth — unauthenticated clients can watch, not commit
    user = None
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            result = await db.execute(
                text("SELECT id, display_name FROM users WHERE id = :id"), {"id": payload["sub"]}
            )
            user = result.mappings().first()
        except JWTError:
            pass

    await manager.connect(ws, pool_id)
    try:
        # Send current pool state immediately on connect
        pool_res = await db.execute(
            text("SELECT committed_qty, moq, status FROM pools WHERE id = :id"),
            {"id": pool_id},
        )
        pool = pool_res.mappings().first()
        if pool:
            await ws.send_json({
                "event": "connected",
                "committed_qty": pool["committed_qty"],
                "moq": pool["moq"],
                "status": pool["status"],
                "user": user["display_name"] if user else None,
            })

        # Keep alive — listen for pings from client
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(ws, pool_id)

# ─────────────────────────────────────────
# DEADLINE EXPIRY — run via cron / APScheduler
# ─────────────────────────────────────────
@app.post("/internal/expire-pools")
async def expire_pools(
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
):
    """
    Intended to be called by a cron job / APScheduler every minute.
    Finds open pools past their deadline that haven't hit MOQ and fails them.
    """
    result = await db.execute(
        text("""
            SELECT id FROM pools
            WHERE status = 'open'
              AND deadline <= NOW()
              AND committed_qty < moq
        """)
    )
    expired = result.scalars().all()

    for pool_id in expired:
        await PoolingService.release_all_payments(str(pool_id), db, redis)

    return {"expired_pools": len(expired)}

# ─────────────────────────────────────────
# STRIPE WEBHOOK  (payment event sink)
# ─────────────────────────────────────────
from fastapi import Request

@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig, webhook_secret)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(400, "Invalid signature")

    if event["type"] == "payment_intent.payment_failed":
        intent = event["data"]["object"]
        await db.execute(
            text("UPDATE commitments SET status = 'refunded' WHERE stripe_payment_intent_id = :id"),
            {"id": intent["id"]},
        )
        await db.commit()

    return {"received": True}