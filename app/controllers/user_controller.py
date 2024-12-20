from sqlalchemy.orm import Session
from app.models import user as user_model
from app.schemas import user as user_schema
from fastapi import HTTPException
import bcrypt
from jose import jwt
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def get_user(db: Session, user_id: int):
    db_user = db.query(user_model.User).filter(user_model.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

def get_user_by_username(db: Session, username: str):
    return db.query(user_model.User).filter(user_model.User.username == username).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(user_model.User).offset(skip).limit(limit).all()


def create_user(db: Session, user: user_schema.UserCreate):
    # bytes = user.password.encode('utf-8')   
    # # generating the salt 
    # salt = bcrypt.gensalt()   
    # # Hashing the password 
    hashed_password = get_password_hash(user.password)  
    db_user = user_model.User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def update_user(db: Session, user_id: int, user: user_schema.UserUpdate):
    db_user = get_user(db,user_id)
    
    if user.username:
        db_user.username = user.username
    if user.email:
        db_user.email = user.email
    
    db.commit()
    db.refresh(db_user)
    return db_user


def delete_user(db: Session, user_id: int):
    db_user = get_user(db, user_id)
    db.delete(db_user)
    db.commit()
    return {"ok": True}

def authenticate_user(db: Session, user: user_schema.UserLogin):
    db_user = get_user_by_username(db, username=user.username)
    
    # user_bytes = user.password.encode('utf-8') 
    if not db_user:
         raise HTTPException(status_code=400, detail="Incorrect username or password")
    if not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return db_user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
     to_encode = data.copy()
     if expires_delta:
          expire = datetime.utcnow() + expires_delta
     else:
         expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
     to_encode.update({"exp": expire})
     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
     return encoded_jwt

def verify_token(token:str, db:Session):
     try:
         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
         username = payload.get("username")
         if username is None:
              raise HTTPException(status_code=401, detail="Could not validate credentials")
         token_data = user_schema.TokenData(username=username, exp=payload.get("exp"))
     except jwt.JWTError:
          raise HTTPException(status_code=401, detail="Could not validate credentials")
     user = get_user_by_username(db, username=token_data.username)
     if user is None:
          raise HTTPException(status_code=401, detail="Could not validate credentials")
     return user
 
def get_password_hash(password):
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password=pwd_bytes, salt=salt)
    string_password = hashed_password.decode('utf8')
    return string_password


def verify_password(plain_password, hashed_password):
    password_byte_enc = plain_password.encode('utf-8')
    hashed_password = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_byte_enc, hashed_password)