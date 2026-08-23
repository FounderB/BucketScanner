# Notifications

## Webhook

```bash
bucket-scanner scan --folder-id b1g... \
  --webhook https://hooks.example.com/bucket-scanner
```

Payload includes summary, findings (first 20), and chains as JSON.

## Telegram

```bash
bucket-scanner scan --folder-id b1g... \
  --telegram-token "$BOT_TOKEN" \
  --telegram-chat-id "$CHAT_ID"
```

## Config file

```toml
[notify]
webhook_url = "https://hooks.example.com/bucket-scanner"
telegram_bot_token = "123:abc"
telegram_chat_id = "123456"
min_severity = "high"
```

Then:

```bash
bucket-scanner scan --folder-id b1g... --notify
```

Alerts fire only when findings or chains meet `min_severity`.
