from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode
import base64
import json
import os

CHUNK_SIZE = 128  # For 1024-bit RSA, adjust based on key size

def generate_rsa_keys():
	key = RSA.generate(2048)
	private_pem = key.export_key().decode()
	public_pem = key.publickey().export_key().decode()
	return public_pem, private_pem

def encrypt(plaintext: bytes, public_key_str: str) -> bytes:
	key = RSA.import_key(public_key_str)
	# Encrypt with no padding — deterministic but insecure
	encrypted_chunks = []
	for i in range(0, len(plaintext), CHUNK_SIZE):
		chunk = plaintext[i:i+CHUNK_SIZE]
		enc = key._encrypt(int.from_bytes(chunk, byteorder='big'))
		enc_bytes = enc.to_bytes(key.size_in_bytes(), byteorder='big')
		encrypted_chunks.append(base64.b64encode(enc_bytes).decode())
	return json.dumps(encrypted_chunks).encode()

def decrypt(encrypted_payload: bytes, private_key_str: str) -> bytes:
	key = RSA.import_key(private_key_str)
	encrypted_chunks = json.loads(encrypted_payload.decode())
	decrypted = b''
	for enc_chunk_b64 in encrypted_chunks:
		enc_chunk = base64.b64decode(enc_chunk_b64)
		dec = key._decrypt(int.from_bytes(enc_chunk, byteorder='big'))
		dec_bytes = dec.to_bytes((dec.bit_length() + 7) // 8, byteorder='big')
		decrypted += dec_bytes
	return decrypted