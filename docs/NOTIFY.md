# Notifications

## Webhook (Slack-compatible)

```bash
bucket-scanner scan --folder-id b1g... \
  --webhook https://hooks.slack.com/services/... \
  --baseline baselines/yc-prod.json \
  --notify-new-only
```

Payload includes summary, findings (first 20), chains, `new_only`, and Slack-style `blocks` with mrkdwn text.

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
new_only = true
```

Then:

```bash
bucket-scanner scan --folder-id b1g... --notify --baseline baselines/prod.json
```

Alerts fire only when findings or chains meet `min_severity`. With `new_only = true` (or `--notify-new-only`) and a baseline, only **new** findings/chains are notified — ideal for nightly drift alerts.
