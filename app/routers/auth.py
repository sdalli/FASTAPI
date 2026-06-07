from fastapi import APIRouter, Depends, Request, status, HTTPException
from sqlalchemy.orm import Session

from .. import database, schemas, models, utils, oauth2

router = APIRouter(tags=['Authentication'])


async def get_login_request(request: Request):
    try:
        data = await request.json()
        return schemas.LoginRequest(**data)
    except Exception:
        form = await request.form()
        email = form.get('username') or form.get('email')
        password = form.get('password')
        return schemas.LoginRequest(email=email, password=password)


@router.post("/login", response_model=schemas.Token)
def login(user_credentials: schemas.LoginRequest = Depends(get_login_request), db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.email == user_credentials.email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid Credentials")

    if not utils.verify(user_credentials.password, user.password):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid Credentials")

    access_token = oauth2.create_access_token(data={"user_id": user.id})
    return {"access_token": access_token, "token_type": "bearer"}


