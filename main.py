from fastapi import FastAPI, Request, Form, Depends,HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from database import get_db
from models import User
from passlib.context import CryptContext

app = FastAPI()

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.get("/", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})





@app.post("/register_user")
def register_user(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Check if username already exists
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists. Please choose another one.")

    if len(password) > 72:
        raise HTTPException(status_code=400, detail="Password must be 72 characters or less")

    hashed_pw = pwd_context.hash(password[:72])
    user = User(username=username, password=hashed_pw)
    db.add(user)
    db.commit()
    return RedirectResponse("/", status_code=303)


@app.post("/login_user")
def login_user(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if user and pwd_context.verify(password, user.password):
        return RedirectResponse("/", status_code=303)
    return {"error": "Invalid username or password"}
