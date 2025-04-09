from fastapi import FastAPI, Depends, HTTPException, Form
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
import hashlib
from typing import *
from base64 import b64encode, b64decode
from datetime import datetime, timedelta

from Encrypt import encrypt, decrypt, generate_rsa_keys
from Sign import sign, verify_signature

# JWT Configuration
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()
# filename - priv key
db_sign_keys : Dict[str, str] = {}
db_files: Dict[str, Dict] = {}
db_users: Dict[str, str] = {}

class User(BaseModel):
	username: str
	password: str

class Token(BaseModel):
	access_token: str
	token_type: str

def verify_password(plain_password, hashed_password):
	return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
	return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(hours=1)):
	to_encode = data.copy()
	expire = datetime.utcnow() + expires_delta
	to_encode.update({"exp": expire})
	return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
		username: str = payload.get("sub")
		if username is None or username not in db_users:
			raise HTTPException(status_code=401, detail="Invalid authentication credentials")
		return username
	except JWTError:
		raise HTTPException(status_code=401, detail="Invalid authentication credentials")

@app.post("/register")
def register(user: User):
	if user.username in db_users:
		raise HTTPException(status_code=400, detail="User already exists")

	# Hash Password
	db_users[user.username] = get_password_hash(user.password)

	return {"message": "User registered successfully"}

@app.post("/login", response_model=Token)
def login(user: User):
	if user.username not in db_users or not verify_password(user.password, db_users[user.username]):
		raise HTTPException(status_code=401, detail="Invalid credentials")
	access_token = create_access_token(data={"sub": user.username})
	return {"access_token": access_token, "token_type": "bearer"}

@app.get("/archivos")
def list_files():
	return [
		{
			"file_name": file_name,
			"signed": bool(file_data.get("signature")),
			"hash": file_data.get("hash")
		}
		for file_name, file_data in db_files.items()
	]

@app.post("/guardar")
def upload_file(
	file_name: str = Form(...),
	file_data: str = Form(...),
	file_pub_key: str = Form(...),
	sign_priv_key: Optional[str] = Form(None),
	username: str = Depends(get_current_user)
):
	if username not in db_users:
		raise HTTPException(status_code=400, detail="User not registered")

	file_hash = hashlib.sha256(b64decode(file_data)).hexdigest()

	signature = None
	if sign_priv_key:
		signature = sign(b64decode(file_data), sign_priv_key)

	db_files[f"@{username} : {file_name}"] = {
		"hash": file_hash,
		"signature": signature,
		"file_pub_key": file_pub_key,
		"content": file_data
	}

	return {"filename": file_name, "filesize": len(file_data), "signature": signature, "hash": file_hash}

@app.get("/archivos/{filename}/descargar")
def download_file(
	filename: str,
	username: str = Depends(get_current_user)
):
	if username not in db_users:
		raise HTTPException(status_code=400, detail="User not registered")

	if filename not in db_files:
		raise HTTPException(status_code=400, detail="File not found")

	file_data = db_files[filename]["content"]

	return {
		"filename": filename.rsplit(" : ", 1)[-1],
		"content": file_data,
		"file_pub_key": db_files[filename]["file_pub_key"]
	}

@app.post("/verificar")
def verify_file(
	file_name: str = Form(...),
	file_data: str = Form(...),
	sign_pub_key: str = Form(...),
	username: str = Depends(get_current_user)
):
	if username not in db_users:
		raise HTTPException(status_code=400, detail="User not registered")

	if f"@{username} : {file_name}" not in db_files:
		raise HTTPException(status_code=400, detail="File not found")

	remote_file = db_files[f"@{username} : {file_name}"]

	file_hash = hashlib.sha256(b64decode(file_data)).hexdigest()

	if file_hash != remote_file["hash"]:
		raise HTTPException(status_code=400, detail=f"Hash mismatch:\n\tRemote: {remote_file['hash']}\n\tLocal:  {file_hash}")

	signature = remote_file["signature"]
	if not signature:
		raise HTTPException(status_code=400, detail="File on Remote is not signed, But both Hashes are the same.")

	try:
		if verify_signature(b64decode(file_data), remote_file["signature"], sign_pub_key):
			return {"message": "Signature is valid"}
		else:
			raise HTTPException(status_code=400, detail="Invalid signature")
	except:
		raise HTTPException(status_code=400, detail="Invalid signature")