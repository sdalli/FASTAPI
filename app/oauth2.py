from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from app import models
from . import schemas
from .database import get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f3a534931eec0db2910dd7"
ALGORITHM = "HS256" 
access_token_expire_minutes = 30

def create_access_token(data: dict):
    # Minimal token stub for now. Replace with JWT for production.
   # return f"token-{data.get('user_id')}"
   to_encode = data.copy()
   expire = datetime.utcnow() + timedelta(minutes=access_token_expire_minutes)
   to_encode.update({"exp": expire})

   return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)    


def verify_access_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        id: str = payload.get("user_id")
        if id is None:
            raise credentials_exception
        token_data = schemas.TokenData(id=id)
    except JWTError:
        raise credentials_exception
    return token_data

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = verify_access_token(token, credentials_exception)

    user = db.query(models.User).filter(models.User.id == token.id).first()

    return user


