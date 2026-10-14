from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
import bcrypt
from pydantic import BaseModel

# secret key used to sign the tokens 
SECRET_KEY = "my-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# password hashing setup using bcrypt
def hash_password(password: str) -> str:
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )

# token comes via an authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI(title="Auth & RBAC Simulation")

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   
    allow_methods=["*"],
    allow_headers=["*"],      
)

test_users_db = {
    "student_user": {
        "username": "student_user",
        "hashed_password": hash_password("student123"),
        "role": "user",
    },
    "admin_user": {
        "username": "admin_user",
        "hashed_password": hash_password("admin123"),
        "role": "admin",
    },
}

# data models 
class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class UserProfile(BaseModel):
    username: str
    role: str

# helper functions 
def create_jwt_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Packages user information and expiration time into a signed token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    """
    Decodes the incoming token, checks if it is valid,
    and returns the user profile from the database.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try: 
        # verify & decode the jwt 
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    user = test_users_db.get(username)
    if user is None:
        raise credentials_exception
    return user 

def require_role(required_role: str):
    """
    RBAC: Checks if the logged-in user has the specific role needed.
    """
    def role_checker(current_user: Annotated[dict, Depends(get_current_user)]):
        if current_user["role"] != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: You need the '{required_role}' role to access this resource."
            )
        return current_user
    return role_checker


# endpoints 

@app.post("/login", response_model=TokenResponse)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """
    Authentication Step: 
    User submits username and password.
    Returns a JWT access if credentials match.
    """

    user = test_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password",
        )

    # put username and role inside the token payload
    token = create_jwt_token(
        data={"sub": user["username"], "role": user["role"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": token, "token_type": "bearer"}

@app.get("/profile", response_model=UserProfile)
async def view_profile(current_user: Annotated[dict, Depends(get_current_user)]):
    """
    AUTHENTICATED ONLY:
    Any user with a valid token (regardless of role) can see this.
    """
    return current_user


@app.get("/admin/settings")
async def view_admin_settings(admin_user: Annotated[dict, Depends(require_role("admin"))]):
    """
    RBAC (AUTHORIZATION) STEP:
    Only accessible if the user's role is 'admin'.
    """
    return {
        "message": f"Welcome {admin_user['username']}! You have access to administrative settings.",
        "status": "Authorized",
    }