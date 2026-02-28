import re
import pandas as pd

FAILED_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
ACCEPTED_RE = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
IP_RE = re.compile(r"from (?P<ip>\d+\.\d+\.\d+\.\d+)")

def parse_logs(text: str) -> pd.DataFrame:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        m = FAILED_RE.search(line)
        if m:
            rows.append({"event": "failed_login", "user": m.group("user"), "ip": m.group("ip"), "raw": line})
            continue

        m = ACCEPTED_RE.search(line)
        if m:
            rows.append({"event": "success_login", "user": m.group("user"), "ip": m.group("ip"), "raw": line})
            continue

        m = IP_RE.search(line)
        ip = m.group("ip") if m else None
        rows.append({"event": "other", "user": None, "ip": ip, "raw": line})

    return pd.DataFrame(rows)