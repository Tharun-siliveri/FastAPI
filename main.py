from fastapi import FastAPI, HTTPException, Depends, status, Query, File, UploadFile
from minio import Minio
from minio.error import S3Error
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
import jwt
import datetime
from typing_extensions import Annotated
from typing import Union, List, Optional
from jwt.exceptions import InvalidTokenError
from fastapi.middleware.cors import CORSMiddleware


from database import get_connection, close_connection

from dotenv import load_dotenv
import io
import os

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(BaseModel):
    username: str
    password: str
    # disabled: Union[bool, None] = None

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

# root route
@app.get("/")
async def root():
    return {"message": "Hello World"}


# to login the user
@app.post("/login")
async def login(user: User):
    db_user = authenticate_user(user.username, user.password)
    if not db_user:
        print("Invalid credentials")
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token(data={"name": db_user['username']})
    return {"access_token": access_token, "token_type": "bearer"}




oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class TokenData(BaseModel):
    username: Union[str, None] = None

class RegUser(BaseModel):
    username: str
    first_name: str
    last_name: str
    email: str
    password: str
    # disabled: Union[bool, None] = None

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
        username: str = payload.get("name")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user



async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    # if current_user.get('disabled'):
    #     raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# to get the current user
@app.get("/users/me/", response_model=RegUser)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


# to register the user
@app.post("/register")
async def register(user: RegUser):
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s", (user.username,))
    existing_user = cursor.fetchone()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    cursor.execute("INSERT INTO users (username, first_name, last_name, email, password) VALUES (%s, %s, %s, %s, %s)", (user.username, user.first_name, user.last_name, user.email, get_password_hash(user.password)))  
    connection.commit()
    close_connection(connection)
    return {"message": "User registered successfully"}


# to update the user of me
@app.put("/users/me/")
async def update_user(user: RegUser, current_user: Annotated[User, Depends(get_current_active_user)]):
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("UPDATE users SET username=%s, first_name=%s, last_name=%s, email=%s, password=%s WHERE username=%s", (user.username, user.first_name, user.last_name, user.email, get_password_hash(user.password), current_user['username']))
    connection.commit()
    close_connection(connection)
    return {"message": "User updated successfully"}



# now lets create filters to get users based on the query params

@app.get("/users")
async def get_users(
    # current_user: Annotated[User, Depends(get_current_active_user)],
    username: Optional[str] = Query(None),
    email: Optional[str] = Query(None),
    first_name: Optional[str] = Query(None),
    last_name: Optional[str] = Query(None),
):
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    query = "SELECT * FROM users"
    conditions = []
    values = []

    if username:
        conditions.append("username LIKE %s")
        values.append(f"%{username}%")
    if email:
        conditions.append("email LIKE %s")
        values.append(f"%{email}%")
    if first_name:
        conditions.append("first_name LIKE %s")
        values.append(f"%{first_name}%")
    if last_name:
        conditions.append("last_name LIKE %s")
        values.append(f"%{last_name}%")

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    cursor.execute(query, values)
    users = cursor.fetchall()
    close_connection(connection)
    return users


MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")
MINIO_BUCKET_NAME = os.getenv("MINIO_BUCKET_NAME")

# Initialize Minio client
minio_client = Minio(
    MINIO_ENDPOINT,
    access_key=MINIO_ACCESS_KEY,
    secret_key=MINIO_SECRET_KEY,
    secure=False 
)

# Create bucket if it does not exist
if not minio_client.bucket_exists(MINIO_BUCKET_NAME):
    minio_client.make_bucket(MINIO_BUCKET_NAME)

MAX_FILE_SIZE_MB = 5
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

@app.post("/upload")
async def upload_documents(files: list[UploadFile] = File(...)):
    try:
        for file in files:
            file_data = await file.read()
            file_size = len(file_data)
            
            if file_size > MAX_FILE_SIZE_BYTES:
                raise HTTPException(status_code=400, detail=f"File '{file.filename}' exceeds the maximum allowed size of {MAX_FILE_SIZE_MB} MB")

            file_name = file.filename

            # Upload the file to MinIO using the put_object API call
            minio_client.put_object(
                bucket_name=MINIO_BUCKET_NAME,
                object_name=file_name,
                data=io.BytesIO(file_data),
                length=file_size,
                content_type=file.content_type
            )

        return {"message": "Files uploaded successfully"}
    except S3Error as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/download")
async def download_document(file_name: str):
    try:
        # Check if the object exists before generating a presigned URL
        found = minio_client.stat_object(MINIO_BUCKET_NAME, file_name)
        
        # If found, generate a presigned URL for downloading the file
        presigned_url = minio_client.presigned_get_object(
            bucket_name=MINIO_BUCKET_NAME,
            object_name=file_name,
            expires=datetime.timedelta(hours=1)  # URL valid for 1 hour
        )
        return {"url": presigned_url}
    except S3Error as e:
        # Handle the case where the file does not exist
        if e.code == "NoSuchKey":
            raise HTTPException(status_code=404, detail="File not found")
        else:
            raise HTTPException(status_code=500, detail=str(e))

@app.get("/blob")
async def get_blob(file_name: str):
    try:
        # Check if the file exists by retrieving its metadata
        minio_client.stat_object(MINIO_BUCKET_NAME, file_name)
        
        # Fetch the file from MinIO
        response = minio_client.get_object(MINIO_BUCKET_NAME, file_name)
        
        # Get the content type (you might want to store and retrieve this if necessary)
        content_type = response.headers.get('Content-Type', 'application/octet-stream')

        # Stream the file content as a response with appropriate headers
        return StreamingResponse(
            io.BytesIO(response.read()), 
            media_type=content_type,
            headers={
                "Content-Disposition": f"attachment; filename={file_name}"
            }
        )
    except S3Error as e:
        # Handle errors, such as the file not existing
        if e.code == "NoSuchKey":
            raise HTTPException(status_code=404, detail="File not found")
        else:
            raise HTTPException(status_code=500, detail=str(e))
        
# Aptus_Generative-AI_Whitepaper_compressed.pdf