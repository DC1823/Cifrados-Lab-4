from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
import hashlib
import rsa
from typing import *

# Configuración JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

db_keys: Dict[str, rsa.PrivateKey] = {}  # Almacena claves privadas de usuarios
db_files: Dict[str, Dict] = {}  # Almacena archivos y sus hashes
db_users: Dict[str, str] = {}  # Simulación de base de datos en memoria

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

def create_access_token(data: dict):
	return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/register")
def register(user: User):
	if user.username in db_users:
		raise HTTPException(status_code=400, detail="User already exists")
	db_users[user.username] = get_password_hash(user.password)
	(pub_key, priv_key) = rsa.newkeys(2048)
	db_keys[user.username] = priv_key  # Almacenar clave privada (esto debe manejarse con más seguridad en producción)
	print(f"Users: {db_users.keys()}")
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
def download_file(filename: str):
	if filename not in db_files:
		raise HTTPException(status_code=404, detail="File not found")
	return {"filename": filename, "content": db_files[filename]["content"].decode(), "public_key": db_files[filename]["public_key"]}

@app.post("/guardar")
def save_file(file: UploadFile = File(...), username: str = "anonymous", sign: bool = False):
	if username not in db_keys:
		raise HTTPException(status_code=400, detail="User not registered")
	contents = file.file.read()
	file_hash = hashlib.sha256(contents).hexdigest()
	signature = None
	if sign:
		signature = rsa.sign(file_hash.encode(), db_keys[username], 'SHA-256').hex()
	db_files[file.filename] = {"hash": file_hash, "content": contents, "signature": signature, "public_key": db_keys[username].publickey().save_pkcs1().decode()}
	return {"filename": file.filename, "hash": file_hash, "signature": signature}

@app.post("/verificar")
def verify_file(filename: str, signature: str, public_key: str):
	if filename not in db_files:
		raise HTTPException(status_code=400, detail="File not found")
	file_hash = db_files[filename]["hash"].encode()
	pub_key = rsa.PublicKey.load_pkcs1(public_key.encode())
	try:
		rsa.verify(file_hash, bytes.fromhex(signature), pub_key)
		return {"message": "Signature is valid"}
	except rsa.VerificationError:
		raise HTTPException(status_code=400, detail="Invalid signature")