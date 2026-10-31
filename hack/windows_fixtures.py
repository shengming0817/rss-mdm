"""Disposable cryptographic inputs for candidate verification. No private material enters Git."""
import json
import os
from pathlib import Path
import secrets

def generate(root):
    root = Path(root)
    (root/"protocol.key").write_bytes(secrets.token_bytes(32))
    for path in root.iterdir():
        if path.is_file() and (path.suffix in (".key", ".pk8") or path.name.endswith("-secret")):
            os.chmod(path, 0o600)
    config = {
        "enrollment":{"origin":"https://localhost:8443"},
        "management":{"origin":"https://localhost:8444"},
        "protocol_protection":{"active_file":str(root/"protocol.key"),"historical_files":[],"fingerprint_file":str(root/"protocol.key")}, "provider_id":"RSS-MDM", "push":None, "additional_management":[], "poll":{'interval_for_first_set_of_retries': 15, 'number_of_first_retries': 10, 'interval_for_second_set_of_retries': 0, 'number_of_second_retries': 0, 'interval_for_remaining_scheduled_retries': 1440, 'number_of_remaining_scheduled_retries': 0, 'poll_on_login': False, 'all_users_poll_on_first_login': False},
    }
    (root/"windows.json").write_text(json.dumps(config))
    return config
