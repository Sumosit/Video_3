from fastapi import FastAPI, Depends, status, Request, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel, create_model
from typing import List
import openai
import asyncio
import httpx
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.backends import default_backend
import logging
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Domain Layer
class User(BaseModel):
    id: int
    email: str
    full_name: str
    disabled: bool
    role: str

class TokenData(BaseModel):
    sub: str = None
    role: str = None

# Application Layer
class UserService:
    def __init__(self, user_repository):
        self.user_repository = user_repository

    async def get_user(self, username: str):
        return await self.user_repository.get_user(username)

    async def get_current_user(self, token: str):
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            sub: str = payload.get("sub")
            role: str = payload.get("role")
            if sub is None or role is None:
                raise credentials_exception
            token_data = TokenData(sub=sub, role=role)
        except JWTError:
            raise credentials_exception
        user = await self.user_repository.get_user(token_data.sub)
        if user is None:
            raise credentials_exception
        return user

    async def get_current_active_admin_user(self, user: User):
        if user.disabled:
            raise HTTPException(status_code=400, detail="Inactive user")
        if user.role != "admin":
            raise HTTPException(status_code=403, detail="Not enough permissions")
        return user

# Infrastructure Layer
class UserRepository:
    def __init__(self, users):
        self.users = users

    async def get_user(self, username: str):
        query = self.users.select().where(self.users.c.email == username)
        user = await database.fetch_one(query)
        if user:
            return User(**user)
        return None

# Database setup
import databases
import sqlalchemy as sa

DATABASE_URL = "postgresql://user:password@localhost/dbname"
database = databases.Database(DATABASE_URL)
metadata = sa.MetaData()
users = sa.Table(
    "users",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("email", sa.String, unique=True, index=True),
    sa.Column("full_name", sa.String),
    sa.Column("hashed_password", sa.String),
    sa.Column("disabled", sa.Boolean, default=False),
    sa.Column("role", sa.String, default="user"),
)
engine = sa.create_engine(DATABASE_URL)
metadata.create_all(engine)

# FastAPI app
app = FastAPI()

# JWT Config
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"

# RSA Keys for encryption and verification
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Serialize keys for use
private_pem = private_key.private_bytes(
    encoding=crypto_serialization.Encoding.PEM,
    format=crypto_serialization.PrivateFormat.PKCS8,
    encryption_algorithm=crypto_serialization.NoEncryption()
)
public_pem = public_key.public_bytes(
    encoding=crypto_serialization.Encoding.PEM,
    format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo
)

# Helper functions for RSA encryption and verification
def encrypt_jwt_with_rsa(jwt_token: str, pub_key_pem: bytes) -> bytes:
    """Encrypts a JWT token using RSA public key encryption."""
    pub_key = crypto_serialization.load_pem_public_key(pub_key_pem, backend=default_backend())
    encrypted = pub_key.encrypt(
        jwt_token.encode('utf-8'),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(crypto_hashes.SHA256()),
            algorithm=crypto_hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def verify_jwt_with_rsa(encrypted_bytes: bytes, pub_key_pem: bytes) -> dict:
    """Decrypts the RSA encrypted JWT token and verifies its signature."""
    pub_key = crypto_serialization.load_pem_public_key(pub_key_pem, backend=default_backend())
    try:
        decrypted_bytes = pub_key.decrypt(
            encrypted_bytes,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(crypto_hashes.SHA256()),
                algorithm=crypto_hashes.SHA256(),
                label=None
            )
        )
        jwt_token = decrypted_bytes.decode('utf-8')
        payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid RSA token or verification failed: {str(e)}")

# Example usage of encrypting and verifying JWTs

def create_jwt(data: dict) -> str:
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/generate-rsa-jwt")
async def generate_encrypted_jwt():
    token_data = {"sub": "user@example.com", "role": "user"}
    token = create_jwt(token_data)
    encrypted_bytes = encrypt_jwt_with_rsa(token, public_pem)
    return {"encrypted": encrypted_bytes.hex()}

@app.post("/verify-rsa-jwt")
async def verify_encrypted_jwt(encrypted_token_hex: str):
    encrypted_bytes = bytes.fromhex(encrypted_token_hex)
    payload = verify_jwt_with_rsa(encrypted_bytes, public_pem)
    return payload

# Middleware to authenticate and forward requests
from starlette.middleware.base import BaseHTTPMiddleware

class AuthProxyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
        token = auth_header[len('Bearer '):]
        # Verify or decrypt JWT
        try:
            payload = verify_jwt_with_rsa(bytes.fromhex(token), public_pem)
        except HTTPException:
            # Try to verify as normal JWT
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            except JWTError:
                raise HTTPException(status_code=401, detail="Invalid token")
        # Attach user info to request state
        request.state.user = payload
        # Forward the request to internal API
        internal_url = f"http://internal-api.local{request.url.path}"
        async with httpx.AsyncClient() as client:
            body = await request.body()
            try:
                response = await client.request(
                    method=request.method,
                    url=internal_url,
                    headers=dict(request.headers),
                    content=body
                )
            except httpx.RequestError as e:
                raise HTTPException(status_code=502, detail=f"Error forwarding request: {str(e)}")
        return response

app.add_middleware(AuthProxyMiddleware)

# Dependency for OAuth2
from fastapi import Depends
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Initialize user repository and service
user_repo = UserRepository(users)
user_service = UserService(user_repo)

# Startup and shutdown events
@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# Generate Pydantic model for request validation
class Item(BaseModel):
    name: str
    description: str = None
    price: float
    tags: List[str] = []

# Generate JSON schema from Pydantic model
item_schema = Item.schema()

# Endpoint that uses the generated schema for validation
@app.post("/items/")
async def create_item(item: Item):
    return item

# Example protected endpoint
@app.get("/users/me", response_model=User)
async def read_users_me(token: str = Depends(oauth2_scheme)):
    user = await user_service.get_current_user(token)
    return user

# Example admin-only endpoint
@app.get("/admin-only")
async def admin_only(user: User = Depends(user_service.get_current_user)):
    await user_service.get_current_active_admin_user(user)
    return {"message": "Welcome, admin!"}
