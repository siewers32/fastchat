from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from config import database
from app.schemas import user as user_schema
from app.controllers import user_controller as controller
from typing import List
from fastapi.middleware.cors import CORSMiddleware
import logging
from fastapi.security import OAuth2PasswordBearer
from datetime import timedelta

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')



database.Base.metadata.create_all(bind=database.engine)

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
@app.post("/token", response_model=user_schema.Token)
def login_for_access_token(form_data: user_schema.UserLogin, db: Session = Depends(database.get_db)):
    user = controller.authenticate_user(db, form_data)
    access_token = controller.create_access_token(data={"username": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/", response_model=List[user_schema.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    users = controller.get_users(db, skip=skip, limit=limit)
    return users


@app.get("/users/{user_id}", response_model=user_schema.User)
def read_user(user_id: int, db: Session = Depends(database.get_db)):
    return controller.get_user(db, user_id=user_id)


@app.post("/users/", response_model=user_schema.User, status_code=201)
def create_user(user: user_schema.UserCreate, db: Session = Depends(database.get_db), current_user: user_schema.User = Depends(controller.verify_token)):
    db_user = controller.get_user_by_username(db, username=user.username)
    if db_user:
         raise HTTPException(status_code=400, detail="Username already taken")
    return controller.create_user(db=db, user=user)


@app.put("/users/{user_id}", response_model=user_schema.User)
def update_user(user_id: int, user: user_schema.UserUpdate, db: Session = Depends(database.get_db)):
    return controller.update_user(db=db,user_id=user_id, user=user)


@app.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int, db: Session = Depends(database.get_db)):
    return controller.delete_user(db=db, user_id=user_id)