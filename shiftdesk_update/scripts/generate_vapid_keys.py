import base64
from cryptography.hazmat.primitives.asymmetric import ec

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

private_key = ec.generate_private_key(ec.SECP256R1())
private_value = private_key.private_numbers().private_value
private_key_bytes = private_value.to_bytes(32, "big")

public_key = private_key.public_key()
public_numbers = public_key.public_numbers()
x = public_numbers.x.to_bytes(32, "big")
y = public_numbers.y.to_bytes(32, "big")
public_key_bytes = b"\x04" + x + y

print("VAPID_PUBLIC_KEY=" + b64url(public_key_bytes))
print("VAPID_PRIVATE_KEY=" + b64url(private_key_bytes))
print("VAPID_SUB=mailto:your-email@example.com")
