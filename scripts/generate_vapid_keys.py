from py_vapid import Vapid

vapid = Vapid()
vapid.generate_keys()

print("Add these Environment Variables in Render:")
print("VAPID_PUBLIC_KEY=" + vapid.public_key)
print("VAPID_PRIVATE_KEY=" + vapid.private_key)
print("VAPID_SUB=mailto:your-email@example.com")
