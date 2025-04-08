from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
import hashlib
import rsa
from typing import Dict
from base64 import b64encode, b64decode
from datetime import datetime, timedelta

from Encrypt import encrypt, decrypt

# JWT Configuration
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

db_keys: Dict[str, rsa.PrivateKey] = {}
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
	db_users[user.username] = get_password_hash(user.password)
	(pub_key, priv_key) = rsa.newkeys(2048)
	db_keys[user.username] = priv_key
	return {"message": "User registered successfully", "public_key": pub_key.save_pkcs1().decode()}

@app.post("/login", response_model=Token)
def login(user: User):
	if user.username not in db_users or not verify_password(user.password, db_users[user.username]):
		raise HTTPException(status_code=401, detail="Invalid credentials")
	access_token = create_access_token(data={"sub": user.username})
	return {"access_token": access_token, "token_type": "bearer"}

@app.get("/archivos")
def list_files():
	return list(db_files.keys())

@app.get("/archivos/{filename}/descargar")
def download_file(filename: str, username: str = Depends(get_current_user)):
	if filename not in db_files:
		raise HTTPException(status_code=404, detail="File not found")

	priv_key = db_keys.get(username)
	if not priv_key:
		raise HTTPException(status_code=400, detail="No private key for user")

	try:
		encrypted = b64decode(db_files[filename]["content"])
		chunk_size = 256
		chunks = [encrypted[i:i+chunk_size] for i in range(0, len(encrypted), chunk_size)]
		decrypted = b"".join(chunks)
	except Exception as e:
		raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")

	return {
		"filename": filename,
		"content": decrypted.decode(errors="ignore"),
		"public_key": db_files[filename]["public_key"]
	}

@app.post("/guardar")
def save_file(file: UploadFile = File(...), sign: bool = False, username: str = Depends(get_current_user)):
	if username not in db_keys:
		raise HTTPException(status_code=400, detail="User not registered")

	contents = file.file.read()
	file_hash = hashlib.sha256(contents).hexdigest()

	priv_key = db_keys[username]
	try:
		chunks = [rsa.sign(contents[i:i+128], priv_key, 'SHA-256') for i in range(0, len(contents), 128)]
		encrypted = b"".join(chunks)
	except Exception as e:
		raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")

	signature = None
	if sign:
		signature = rsa.sign(file_hash.encode(), priv_key, 'SHA-256').hex()

	public_key_pem = rsa.PublicKey(priv_key.n, priv_key.e).save_pkcs1().decode()

	db_files[file.filename] = {
		"hash": file_hash,
		"content": b64encode(encrypted).decode(),
		"signature": signature,
		"public_key": public_key_pem
	}

	return {"filename": file.filename, "hash": file_hash, "signature": signature}

@app.post("/verificar")
def verify_file(file: UploadFile = File(...), signature: str = "", public_key: str = ""):
	contents = file.file.read()
	file_hash = hashlib.sha256(contents).hexdigest().encode()
	pub_key = rsa.PublicKey.load_pkcs1(public_key.encode())
	try:
		rsa.verify(file_hash, bytes.fromhex(signature), pub_key)
		return {"message": "Signature is valid"}
	except rsa.VerificationError:
		raise HTTPException(status_code=400, detail="Invalid signature")