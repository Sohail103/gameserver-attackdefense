### Generating SSL Certificates

To enable HTTPS (required for secure flag operations):

```bash
python generate_ssl_cert.py
```

This creates:
- `cert.pem` - SSL certificate
- `key.pem` - Private key

### Starting Server with HTTPS

```bash
python main.py --ssl-cert cert.pem --ssl-key key.pem
```

## 📡 Public API Endpoints

**Base URL**: `https://YOUR_SERVER_IP:5000` (or `http://` without SSL)

All endpoints accept and return JSON.

---

### 1. Generate Flag

**Endpoint**: `POST /api/generate_flag`

**Purpose**: Services call this to get their current flag. Each service on each team has one active flag at a time. Requesting a new flag replaces the old one.

**Request Body**:
```json
{
  "team": "team-alpha",
  "service": "web-server"
}
```

**Fields**:
- `team` (string, required): The team name that owns the service
- `service` (string, required): The service identifier (e.g., "web-server", "ssh", "database")

**Success Response** (200):
```json
{
  "success": true,
  "flag": "FLAG{team-alpha_web-server_a1b2c3d4e5f6...}",
  "message": "Flag generated successfully"
}
```

**Error Response** (400):
```json
{
  "success": false,
  "flag": "",
  "message": "Unknown team"
}
```

**Example - curl**:
```bash
curl -X POST https://10.0.0.1:5000/api/generate_flag \
  -H "Content-Type: application/json" \
  -k \
  -d '{"team": "team-alpha", "service": "web-server"}'
```

**Example - Python**:
```python
import requests

response = requests.post(
    'https://10.0.0.1:5000/api/generate_flag',
    json={
        'team': 'team-alpha',
        'service': 'web-server'
    },
    verify=False  # For self-signed cert
)

if response.json()['success']:
    flag = response.json()['flag']
    print(f"Got flag: {flag}")
```

**Example - Service Integration**:
```bash
#!/bin/bash
# service_flag_updater.sh - Run this periodically in your service

TEAM="team-alpha"
SERVICE="web-server"
FLAG_FILE="/var/www/flag.txt"

# Get new flag from game server
FLAG=$(curl -s -X POST https://10.0.0.1:5000/api/generate_flag \
  -H "Content-Type: application/json" \
  -k \
  -d "{\"team\":\"$TEAM\",\"service\":\"$SERVICE\"}" \
  | jq -r '.flag')

# Update flag file
if [ ! -z "$FLAG" ] && [ "$FLAG" != "null" ]; then
    echo "$FLAG" > "$FLAG_FILE"
    echo "Flag updated: $FLAG"
fi
```

---

### 2. Submit Flag

**Endpoint**: `POST /api/submit_flag`

**Purpose**: Teams submit captured flags to earn points. Each flag can only be submitted once.

**Request Body**:
```json
{
  "team": "team-bravo",
  "flag": "FLAG{team-alpha_web-server_a1b2c3d4e5f6...}"
}
```

**Fields**:
- `team` (string, required): The team name submitting the flag
- `flag` (string, required): The captured flag string

**Success Response** (200):
```json
{
  "success": true,
  "message": "Valid flag! Captured team-alpha's web-server service",
  "points": 50
}
```

**Error Responses** (200):
```json
{
  "success": false,
  "message": "Invalid or expired flag",
  "points": 0
}
```

```json
{
  "success": false,
  "message": "Cannot submit your own flag",
  "points": 0
}
```

```json
{
  "success": false,
  "message": "Game is not running",
  "points": 0
}
```

**Example - curl**:
```bash
curl -X POST https://10.0.0.1:5000/api/submit_flag \
  -H "Content-Type: application/json" \
  -k \
  -d '{"team": "team-bravo", "flag": "FLAG{team-alpha_web-server_abc123...}"}'
```

**Example - Python**:
```python
import requests

response = requests.post(
    'https://10.0.0.1:5000/api/submit_flag',
    json={
        'team': 'team-bravo',
        'flag': 'FLAG{team-alpha_web-server_abc123...}'
    },
    verify=False
)

result = response.json()
if result['success']:
    print(f"Success! {result['message']} (+{result['points']} points)")
else:
    print(f"Failed: {result['message']}")
```

---

### SSL/HTTPS errors
- Use `-k` flag with curl for self-signed certificates
- Use `verify=False` in Python requests
- Ensure you're using `https://` not `http://` when SSL is enabled
