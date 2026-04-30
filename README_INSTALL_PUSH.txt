# ShiftDesk install + push fix

## PWA install
От аватара натисни „Инсталирай app“. На iPhone: Share → Add to Home Screen.

## In-app известия
Работят веднага: badge, звук и вибрация, когато приложението е отворено.

## Real Web Push
Изисква HTTPS или localhost + pywebpush + VAPID ключове. На локален IP през http:// няма да работи.

```bash
pip install -r requirements_push.txt
```

VAPID ключове може да генерираш с pywebpush/py-vapid или ще ги направим в следващ deploy пакет. Стартиране:

```bash
export VAPID_PUBLIC_KEY="..."
export VAPID_PRIVATE_KEY="..."
export VAPID_SUB="mailto:you@example.com"
python app.py
```

За тест от телефон използвай HTTPS тунел:

```bash
ngrok http 5050
```

Отвори https линка, логни се, натисни „Включи push“, после „Тест push“.
