"""JSON-логер: кожен рядок логу - окремий JSON-об'єкт (формат JSON Lines).
Секрети (паролі, ключі, nonce, IV) у лог НЕ потрапляють - вони маскуються."""
import json
import os
from datetime import datetime, timezone

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "events.log")
SENSITIVE = {"password", "key", "nonce", "iv", "secret", "private_key", "wrapped_key", "salt"}


def _mask(data: dict) -> dict:
    return {k: ("***MASKED***" if k.lower() in SENSITIVE else v) for k, v in data.items()}


def log_event(operation: str, status: str, **details) -> None:
    """operation: encrypt/decrypt/sign/verify/keygen...; status: OK або FAIL."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    record = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "operation": operation,
        "status": status,
        **_mask(details),
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
