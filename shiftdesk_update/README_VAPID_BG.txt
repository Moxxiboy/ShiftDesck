Какво да направиш:

1. Замени файла в проекта:
   scripts/generate_vapid_keys.py

с този от ZIP-а.

2. В Terminal пусни:

python3 scripts/generate_vapid_keys.py

3. Копирай трите реда в Render → Environment:

VAPID_PUBLIC_KEY=...
VAPID_PRIVATE_KEY=...
VAPID_SUB=mailto:твоя_email@example.com

4. Save → Manual Deploy → Deploy latest commit
