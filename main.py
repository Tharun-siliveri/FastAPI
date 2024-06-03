from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
import jwt
import datetime
from typing_extensions import Annotated
from typing import Union
from jwt.exceptions import InvalidTokenError
from fastapi.middleware.cors import CORSMiddleware


from database import get_connection, close_connection

from dotenv import load_dotenv
import os

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(BaseModel):
    username: str
    password: str
    disabled: Union[bool, None] = None

class UserInDB(User):
    hashed_password: str

app = FastAPI()
origins = [
    "http://localhost:3000"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allow all origins if needed
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    # if username is not found check mail also
    if not user:
        cursor.execute("SELECT * FROM users WHERE email=%s", (username,))
        user = cursor.fetchone()
    # print(f"User found: {user}")
    close_connection(connection)
    if user and verify_password(password, user['password']):
        return user
    return None

def create_access_token(data: dict, expires_delta: int = 15):
    to_encode = data.copy()
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=expires_delta)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class TokenData(BaseModel):
    username: Union[str, None] = None

def get_user(username: str):
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    close_connection(connection)
    return user

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

@app.get("/")
async def root():
    return {"message": "Hello World"}

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.get('disabled'):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user

@app.post("/login")
async def login(user: User):
    # print(f"Login attempt for user: {user.username}")
    db_user = authenticate_user(user.username, user.password)
    if not db_user:
        print("Invalid credentials")
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": db_user['username']})
    return {"access_token": access_token, "token_type": "bearer"}

# here i want to create new features like register user...
# register with username , email and password

class RegUser(BaseModel):
    username: str
    email: str
    password: str
    disabled: Union[bool, None] = None

@app.post("/register")
async def register(user: RegUser):
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s", (user.username,))
    existing_user = cursor.fetchone()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (user.username, user.email, get_password_hash(user.password)))
    connection.commit()
    close_connection(connection)
    return {"message": "User registered successfully"}

# get all users 
@app.get("/users")
async def get_users():
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    close_connection(connection)
    return users

# to update the user of me 
@app.put("/users/me/")
async def update_user_me(user: RegUser, current_user: Annotated[User, Depends(get_current_active_user)]):
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("UPDATE users SET username=%s, email=%s, password=%s WHERE id=%s", (user.username, user.email, get_password_hash(user.password), current_user['id']))
    connection.commit()
    close_connection(connection)
    return {"message": "User updated successfully"}