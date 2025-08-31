"""
Secure API with FastAPI + JWT
=============================

## Install
    pip install fastapi uvicorn passlib[bcrypt] fastapi-jwt-auth

## Run
    uvicorn secure_api:app --reload --port 8000

## Endpoints
- POST /register
    Request JSON:
        { "username": "alice", "password": "mypw" }

- POST /login
    Form Data: username, password
    → Returns JWT access token

- GET /profile
    Requires header:
        Authorization: Bearer <token>

## Notes
- Replace `authjwt_secret_key` with a strong random secret in production.
- Always run behind HTTPS in real deployments.
- Consider RS256 (asymmetric) JWT signing for stronger security.
"""

# secure_api.py
# Secure FastAPI implementation with JWT-based auth
# Requirements: pip install fastapi uvicorn passlib[bcrypt] fastapi-jwt-auth

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException

app = FastAPI(title="Secure JWT API")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory user store (for demo only!)
users_db = {}

class UserRegister(BaseModel):
    username: str
    password: str

class Settings(BaseModel):
    # ⚠️ Change this to a strong random secret in production
    authjwt_secret_key: str = "REPLACE_WITH_LONG_RANDOM_SECRET"
    authjwt_algorithm: str = "HS256"
    authjwt_access_token_expires: int = 600  # 10 minutes

@AuthJWT.load_config
def get_config():
    return Settings()

# Proper exception handler for JWT errors
@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": exc.message}
    )

@app.post("/register")
def register(user: UserRegister):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_pw = pwd_context.hash(user.password)
    users_db[user.username] = {"password": hashed_pw}
    return {"msg": "User registered successfully"}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(),
          Authorize: AuthJWT = Depends()):
    user = users_db.get(form_data.username)
    if not user or not pwd_context.verify(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = Authorize.create_access_token(subject=form_data.username)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/profile")
def profile(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    current_user = Authorize.get_jwt_subject()
    return {"user": current_user, "profile": "This is protected user data"}
