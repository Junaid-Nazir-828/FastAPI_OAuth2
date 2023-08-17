from fastapi import Depends , FastAPI , HTTPException , status
from fastapi.security import OAuth2PasswordBearer , OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime , timedelta
from jose import JWTError , jwt
from passlib.context import CryptContext

SECRET_KEY = "gbOBlXktXiupZL/CoKr02j+cAMcJenFksF0oFUqmf6bfgk1Uzi+qW7AWnq2Mbopi"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


fakedb = {
    "Juniad" : {
        "username":"Junaid",
        "fullname":"Junaid Nazir",
        "email" : "junaidnazir7501@gmail.com",
        "hashed_password" : "$2b$12$WTOgHQ/mMB6zYEu8WKU/3ubI.RmbJeVgh3GZe2Xr9k4VQe1xJKyaS",
        "disables":False 
    }
}
# The hash in database is for password : junaid123

class Token(BaseModel):
    access_token : str
    token_type : str

class TokenData(BaseModel):
    username: str or None = None

class User(BaseModel):
    usernames: str
    email: str or None = None
    full_name: str or None = None
    disabled: bool or None = None

class UserInDB(User):
    hashed_password : str

pwd_context = CryptContext(schemes=["bcrypt"],deprecated="auto")
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def verify_password(plain_password,hashedPassword):
    return pwd_context.verify(plain_password,hashedPassword)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db,username:str):
    if username in db:
        userdata = db[username]
        return UserInDB(**userdata) # the two hashterics here pass data as username = "Junaid" , fullname = "Junaid Nazir" ...
    
def authenticate_user(db,username:str,password:str):
    user = get_user(db,username)
    if not user:
        return False
    if not verify_password(password,user.hashed_password):
        return False    
    return user

def create_access_token(data:dict , expires_delta:timedelta or None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp":expire})
    encoded_jwt = jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token : str = Depends(oauth_2_scheme)):
    credentials_expection = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,details = "could not validate credentials",headers = {"WWW-Authenticate":"Bearer"})

    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_expection
        
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_expection

    user = get_user(fakedb,username=token_data.username)
    if user is None:
        raise credentials_expection
    
    return user

async def get_current_active_user(current_user:UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400,detail="Inactive User")
    return current_user

@app.post('/token',response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fakedb,form_data.username,form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Incorrect username or password",headers = {"WWW-Authenticate":"Bearer"})
    access_token_expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub":user.username},expires_delta=access_token_expire)
    return {"access_token":access_token,"token_type":"bearer"}

@app.get("/users/me/",response_model=User)
async def read_user_me(current_user:User = Depends(get_current_active_user)):
    return current_user

@app.get("/users/me/items")
async def read_own_items(current_user:User = Depends(get_current_active_user)):
    return [{"item-id":1,"owner":current_user}]


# since we don't have registeration process so for time being getting hashed password
# pwd = get_password_hash("junaid123")
# print(pwd)