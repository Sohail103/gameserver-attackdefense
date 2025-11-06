# CTF Game Server API Documentation

## 🔒 Security Setup

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

### 3. Get Scoreboard

**Endpoint**: `GET /api/scoreboard`

**Purpose**: Get current game state and team scores.

**Request**: No body required

**Success Response** (200):
```json
{
  "scoreboard": [
    {
      "rank": 1,
      "name": "team-alpha",
      "score": 1050,
      "flags_captured": 3,
      "services_down": 1,
      "last_scan": 1699234567.89
    },
    {
      "rank": 2,
      "name": "team-bravo",
      "score": 980,
      "flags_captured": 2,
      "services_down": 0,
      "last_scan": 1699234567.89
    }
  ],
  "game_info": {
    "status": "running",
    "start_time": 1699234000.0
  }
}
```

**Note**: Team IP addresses are NOT included in the public API for security.

**Example - curl**:
```bash
curl https://10.0.0.1:5000/api/scoreboard -k
```

---

## 🎮 Flag Generation Workflow

### How Services Should Request Flags

1. **Initial Setup**: Each service should request its flag when it starts
2. **Periodic Updates**: Services should request new flags periodically (e.g., every 5-10 minutes)
3. **Store Securely**: Store the flag in a location accessible to your service
4. **Serve to Users**: Make the flag available through your service's vulnerability

### Example Service Setup

```python
#!/usr/bin/env python3
# flag_service.py - Example vulnerable web service

from flask import Flask, render_template
import requests
import threading
import time

app = Flask(__name__)

TEAM_NAME = "team-alpha"
SERVICE_NAME = "web-server"
GAMESERVER_URL = "https://10.0.0.1:5000"
FLAG_UPDATE_INTERVAL = 300  # 5 minutes

current_flag = ""

def update_flag():
    """Background thread to periodically update flag"""
    global current_flag
    while True:
        try:
            response = requests.post(
                f"{GAMESERVER_URL}/api/generate_flag",
                json={"team": TEAM_NAME, "service": SERVICE_NAME},
                verify=False,
                timeout=5
            )
            if response.ok and response.json()['success']:
                current_flag = response.json()['flag']
                print(f"Flag updated: {current_flag}")
        except Exception as e:
            print(f"Failed to update flag: {e}")
        
        time.sleep(FLAG_UPDATE_INTERVAL)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
def admin():
    # Vulnerable endpoint - attackers can get the flag here
    return f"Admin panel\nSecret flag: {current_flag}"

if __name__ == '__main__':
    # Start flag updater thread
    flag_thread = threading.Thread(target=update_flag, daemon=True)
    flag_thread.start()
    
    # Initial flag fetch
    update_flag()
    
    # Run web server
    app.run(host='0.0.0.0', port=8080)
```

---

## 🔧 Common Use Cases

### Attack Script Example

```python
#!/usr/bin/env python3
# exploit.py - Example attack script

import requests

GAMESERVER = "https://10.0.0.1:5000"
MY_TEAM = "team-bravo"
TARGET_IP = "10.0.2.10"

# 1. Exploit the target service to get their flag
flag_response = requests.get(f"http://{TARGET_IP}:8080/admin")
flag = flag_response.text.split("Secret flag: ")[1].strip()

print(f"Captured flag: {flag}")

# 2. Submit the flag to the game server
submit_response = requests.post(
    f"{GAMESERVER}/api/submit_flag",
    json={"team": MY_TEAM, "flag": flag},
    verify=False
)

result = submit_response.json()
if result['success']:
    print(f"Success! {result['message']} (+{result['points']} points)")
else:
    print(f"Failed: {result['message']}")
```

---

## 🔐 Security Notes

1. **Use HTTPS**: Always run the server with SSL certificates to prevent man-in-the-middle attacks
2. **Self-Signed Certs**: When using self-signed certificates, clients must use `-k` (curl) or `verify=False` (Python requests)
3. **Flag Lifetime**: Each flag is valid until it's captured or replaced by a new flag
4. **One Flag Per Service**: Each service+team combination has exactly one active flag at a time
5. **No Self-Capture**: Teams cannot submit their own flags

---

## 📊 Game Mechanics

### Scoring

- **Flag Capture**: +50 points (configurable with `--flag-points`)
- **Service Downtime**: -10 points per missing service per scan (configurable with `--penalty`)

### Flag Format

```
FLAG{team-name_service-name_random-hex-string}
```

Example: `FLAG{team-alpha_web-server_a1b2c3d4e5f6789012345678}`

The format makes it easy to identify which team and service a flag belongs to (useful for debugging), while the random hex ensures uniqueness.

---

## ❓ Troubleshooting

### "Unknown team" error
- Verify your team name matches exactly what's configured in the game server
- Check available teams at the scoreboard web interface

### "Invalid or expired flag" error
- The flag may have been replaced by a newer flag (service requested a new one)
- The flag may have already been submitted by another team
- The flag string may be incorrect

### "Game is not running" error
- Wait for the game organizers to start the game
- Check game status at the scoreboard web interface

### SSL/HTTPS errors
- Use `-k` flag with curl for self-signed certificates
- Use `verify=False` in Python requests
- Ensure you're using `https://` not `http://` when SSL is enabled
