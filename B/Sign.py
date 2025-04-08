from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import base64

def sign(file_bytes: bytes, private_key_str: str) -> str:
	private_key = serialization.load_pem_private_key(
		private_key_str.encode(), password=None
	)

	signature = private_key.sign(
		file_bytes,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH
		),
		hashes.SHA256()
	)

	# Return base64 signature for safe transport
	return base64.b64encode(signature).decode()

def verify_signature(file_bytes: bytes, signature_b64: str, public_key_str: str) -> bool:
	public_key = serialization.load_pem_public_key(public_key_str.encode())
	signature = base64.b64decode(signature_b64)

	try:
		public_key.verify(
			signature,
			file_bytes,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)
		return True
	except Exception:
		return False