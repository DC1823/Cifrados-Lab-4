from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os
import base64
import json

def generate_rsa_keys():
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048
	)

	private_pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	)

	public_pem = private_key.public_key().public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

	return public_pem.decode(), private_pem.decode()

def encrypt(plaintext: bytes, public_key_str: str) -> bytes:
	public_key = serialization.load_pem_public_key(public_key_str.encode())

	# Generate a random AES key and IV
	aes_key = os.urandom(32)  # AES-256
	iv = os.urandom(16)       # For AES CBC

	# Encrypt the plaintext using AES
	cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()

	# Pad plaintext to multiple of 16 bytes
	padding_len = 16 - (len(plaintext) % 16)
	plaintext_padded = plaintext + bytes([padding_len] * padding_len)
	encrypted_data = encryptor.update(plaintext_padded) + encryptor.finalize()

	# Encrypt the AES key using RSA
	encrypted_key = public_key.encrypt(
		aes_key,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)

	# Return encrypted_key + iv + encrypted_data, base64 encoded
	payload = {
		'key': base64.b64encode(encrypted_key).decode(),
		'iv': base64.b64encode(iv).decode(),
		'data': base64.b64encode(encrypted_data).decode()
	}

	return json.dumps(payload).encode()

def decrypt(encrypted_payload: bytes, private_key_str: str) -> bytes:
	private_key = serialization.load_pem_private_key(private_key_str.encode(), password=None)
	payload = json.loads(encrypted_payload.decode())

	encrypted_key = base64.b64decode(payload['key'])
	iv = base64.b64decode(payload['iv'])
	encrypted_data = base64.b64decode(payload['data'])

	# Decrypt AES key with RSA
	aes_key = private_key.decrypt(
		encrypted_key,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)

	# Decrypt the actual data
	cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	plaintext_padded = decryptor.update(encrypted_data) + decryptor.finalize()

	# Remove padding
	padding_len = plaintext_padded[-1]
	plaintext = plaintext_padded[:-padding_len]

	return plaintext.decode()