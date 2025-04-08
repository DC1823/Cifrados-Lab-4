from Encrypt import *
from Sign import *

public_key, private_key = generate_rsa_keys()

data = b"Hello, this is a long message that exceeds the RSA limit. " * 10
encrypted = encrypt(data, public_key)
decrypted = decrypt(encrypted, private_key)

print(encrypted)
print("\n" + "-"*40 + "\n")
print(decrypted)

print("\n" + "-"*40 + "\n")
signature = sign(encrypted, private_key)
print(f"Signature: {signature}")
print("Signature Verified!" if verify_signature(encrypted, signature, public_key) else "ERROR Verifying Signature")