import re
from collection import Counter

LOG_FILE = "ssh_logs.txt"

FAILED_RE = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")

ips = []

with open(LOG_FILE, "r") as f:
	for line in f:
		match = FAILED_RE.search(line)
		if match:
			ips.append(match.group(1))

print("Total failed logins:", len(ips))

counter = Counter(ips)
print("\nTop IPs:")
for ip, count in counter.most_common(5):
	print(ip, "->", count)
