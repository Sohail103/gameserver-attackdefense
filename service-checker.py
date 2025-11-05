#!/usr/bin/env python3
"""
checker.py

- Static mapping of teams -> expected TCP ports
- Runs nmap every 10 seconds to validate ports
- Deducts score per missing service per-scan
- Prints and logs scoreboard
- Serves leaderboard via Flask web interface
"""

import subprocess
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, render_template_string, jsonify
from typing import Dict, List

# ----- Configuration ----- #
SCAN_INTERVAL_SECONDS = 10
NMAP_TIMEOUT = 8  # seconds per nmap subprocess
PENALTY_PER_PORT = 10  # points deducted per missing port per scan
# Set to True to run UDP (-sU) in addition to TCP. Requires root + slower scans.
ENABLE_UDP = False

# Example teams map 
TEAMS = {
    "team-a": {
        "ip": "10.0.2.10",
        "expected_tcp_ports": [22, 80, 5000],
        "score": 1000,
    },
    "team-b": {
        "ip": "10.0.2.11",
        "expected_tcp_ports": [22, 7000, 8081],
        "score": 1000,
    },
    "team-test": {
        "ip": "127.0.0.1",
        "expected_tcp_ports": [2222, 8001, 8081],
        "score": 1000,
    },
}

# Logging config
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger("ctf-checker")

# Protect shared state
_lock = threading.Lock()

# In-memory historical state (optional)
history = {
    # team_name: { "last_scan": ts, "last_results": {port: "open"/"closed"} }
}


# ----- Helper functions ----- #
def run_nmap(ip: str, ports: List[int], timeout: int = NMAP_TIMEOUT, udp: bool = False) -> Dict[int, str]:
    """
    Run nmap on a host for provided TCP ports (and optionally UDP).
    Returns dict: port -> "open" or "closed"/"filtered"/"unknown"
    Uses: nmap -Pn -p <ports> -oG - ip
    """
    if not ports:
        return {}

    ports_str = ",".join(str(p) for p in ports)
    cmd = ["nmap", "-Pn", "-p", ports_str, "-oG", "-", ip]
    if udp:
        cmd.insert(1, "-sU")  # make it: nmap -sU -Pn ...
    logger.debug("Running nmap: %s", " ".join(cmd))
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout, text=True)
    except subprocess.CalledProcessError as e:
        logger.error("nmap failed (non-zero exit): %s", e.output or str(e))
        return {p: "unknown" for p in ports}
    except subprocess.TimeoutExpired:
        logger.error("nmap timed out for %s:%s", ip, ports_str)
        return {p: "unknown" for p in ports}
    except FileNotFoundError:
        logger.error("nmap binary not found. Install nmap in your environment.")
        return {p: "unknown" for p in ports}

    # Example greppable output line:
    # Host: 10.0.2.15 ()  Ports: 22/open/tcp//ssh///,80/open/tcp//http///
    results = {p: "closed" for p in ports}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Host:"):
            # find "Ports: " section
            if "Ports:" not in line:
                continue
            parts = line.split("Ports:", 1)[1].strip()
            # parts example: "22/open/tcp//ssh///,80/open/tcp//http///"
            for segment in parts.split(","):
                seg = segment.strip()
                if not seg:
                    continue
                # seg format: port/state/proto/...
                seg_parts = seg.split("/")
                try:
                    port = int(seg_parts[0])
                    state = seg_parts[1]
                except Exception:
                    continue
                if port in results:
                    results[port] = state  # e.g., "open" or "filtered"
    return results


def check_team(team_name: str, team_cfg: dict) -> Dict:
    ip = team_cfg["ip"]
    tcp_ports = team_cfg.get("expected_tcp_ports", [])
    udp_ports = team_cfg.get("expected_udp_ports", []) if ENABLE_UDP else []

    tcp_results = run_nmap(ip, tcp_ports, udp= False)
    udp_results = {}
    if ENABLE_UDP and udp_ports:
        udp_results = run_nmap(ip, udp_ports, udp=True)

    timestamp = time.time()
    with _lock:
        history[team_name] = {
            "last_scan": timestamp,
            "tcp_results": tcp_results,
            "udp_results": udp_results,
        }

    # Determine missing services and compute penalty
    missing_tcp = [p for p, state in tcp_results.items() if state != "open"]
    missing_udp = [p for p, state in udp_results.items() if state != "open"]

    total_missing = len(missing_tcp) + len(missing_udp)
    penalty = total_missing * PENALTY_PER_PORT

    if total_missing > 0:
        with _lock:
            team_cfg["score"] = max(0, team_cfg.get("score", 0) - penalty)

    logger.info(
        "Scanned %s (%s): missing tcp=%s udp=%s -> penalty=%d, new_score=%d",
        team_name, ip, missing_tcp, missing_udp, penalty, team_cfg["score"],
    )

    return {
        "team": team_name,
        "ip": ip,
        "missing_tcp": missing_tcp,
        "missing_udp": missing_udp,
        "penalty": penalty,
        "score": team_cfg["score"],
        "timestamp": timestamp,
    }


# ----- Scheduler job ----- #
def scan_all_teams():
    logger.debug("Starting scheduled scan of all teams")
    results = []
    with ThreadPoolExecutor(max_workers=min(16, max(2, len(TEAMS)))) as ex:
        futures = {ex.submit(check_team, name, cfg): name for name, cfg in TEAMS.items()}
        for fut in as_completed(futures):
            try:
                res = fut.result()
                results.append(res)
            except Exception as e:
                logger.exception("Exception scanning team %s: %s", futures[fut], e)
    # After the scan, print a concise scoreboard
    print_scoreboard()


def print_scoreboard():
    with _lock:
        lines = ["\n=== SCOREBOARD ==="]
        for name, cfg in TEAMS.items():
            lines.append(f"{name:20s} {cfg['ip']:15s}  score: {cfg.get('score', 0)}")
        lines.append("==================\n")
    print("\n".join(lines))


# ----- Flask Web Server ----- #
app = Flask(__name__)

# HTML template for the leaderboard table
LEADERBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>CTF Leaderboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; font-weight: bold; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .score { font-weight: bold; color: #0066cc; }
        .refresh { margin-top: 20px; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
    <meta http-equiv="refresh" content="30">
</head>
<body>
    <h1>Attack/Defense Leaderboard</h1>
    <p class="timestamp">Last updated: {{ timestamp }}</p>
    <table>
        <thead>
            <tr>
                <th>Team Name</th>
                <th>IP Address</th>
                <th>Score</th>
                <th>Missing TCP Ports</th>
                <th>Missing UDP Ports</th>
                <th>Last Scan</th>
            </tr>
        </thead>
        <tbody>
            {% for team in teams %}
            <tr>
                <td>{{ team.name }}</td>
                <td>{{ team.ip }}</td>
                <td class="score">{{ team.score }}</td>
                <td>{{ team.missing_tcp | join(', ') if team.missing_tcp else 'None' }}</td>
                <td>{{ team.missing_udp | join(', ') if team.missing_udp else 'None' }}</td>
                <td>{{ team.last_scan_time }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    <div class="refresh">
        <p><a href="/leaderboard">Refresh</a> | <a href="/api/leaderboard">Raw JSON</a></p>
    </div>
</body>
</html>
"""

@app.route('/leaderboard')
def leaderboard():
    """Serve the leaderboard as a nice HTML table"""
    with _lock:
        teams_data = []
        for name, cfg in TEAMS.items():
            team_history = history.get(name, {})
            last_scan = team_history.get("last_scan", 0)
            last_scan_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_scan)) if last_scan else "Never"
            
            # Get missing ports from last scan
            tcp_results = team_history.get("tcp_results", {})
            udp_results = team_history.get("udp_results", {})
            missing_tcp = [p for p, state in tcp_results.items() if state != "open"]
            missing_udp = [p for p, state in udp_results.items() if state != "open"]
            
            teams_data.append({
                'name': name,
                'ip': cfg['ip'],
                'score': cfg.get('score', 0),
                'missing_tcp': missing_tcp,
                'missing_udp': missing_udp,
                'last_scan_time': last_scan_time
            })
        
        # Sort by score descending
        teams_data.sort(key=lambda x: x['score'], reverse=True)
        current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    
    return render_template_string(LEADERBOARD_TEMPLATE, teams=teams_data, timestamp=current_time)

@app.route('/api/leaderboard')
def api_leaderboard():
    """Serve the raw leaderboard data as JSON"""
    with _lock:
        leaderboard_data = []
        for name, cfg in TEAMS.items():
            team_history = history.get(name, {})
            last_scan = team_history.get("last_scan", 0)
            
            # Get missing ports from last scan
            tcp_results = team_history.get("tcp_results", {})
            udp_results = team_history.get("udp_results", {})
            missing_tcp = [p for p, state in tcp_results.items() if state != "open"]
            missing_udp = [p for p, state in udp_results.items() if state != "open"]
            
            leaderboard_data.append({
                'team_name': name,
                'ip_address': cfg['ip'],
                'score': cfg.get('score', 0),
                'missing_tcp_ports': missing_tcp,
                'missing_udp_ports': missing_udp,
                'last_scan_timestamp': last_scan,
                'expected_tcp_ports': cfg.get('expected_tcp_ports', []),
                'expected_udp_ports': cfg.get('expected_udp_ports', [])
            })
        
        # Sort by score descending
        leaderboard_data.sort(key=lambda x: x['score'], reverse=True)
    
    return jsonify({
        'leaderboard': leaderboard_data,
        'last_updated': time.time(),
        'scan_interval_seconds': SCAN_INTERVAL_SECONDS
    })

@app.route('/')
def index():
    """Redirect root to leaderboard"""
    return leaderboard()

def run_flask_server():
    """Run the Flask server in the background"""
    logger.info("Starting Flask web server on http://0.0.0.0:5555")
    app.run(host='0.0.0.0', port=5555, debug=False, use_reloader=False)


# ----- Main ----- #
def main():
    logger.info("Starting CTF service checker")
    print_scoreboard()

    scheduler = BackgroundScheduler()
    scheduler.add_job(scan_all_teams, "interval", seconds=SCAN_INTERVAL_SECONDS)
    scheduler.start()
    logger.info("Scheduler started (interval=%ds). Press Ctrl-C to exit.", SCAN_INTERVAL_SECONDS)

    try:
        # Run an initial scan immediately (blocking)
        scan_all_teams()
        # Start Flask server in a separate thread
        flask_thread = threading.Thread(target=run_flask_server)
        flask_thread.daemon = True
        flask_thread.start()
        # Sleep forever; scheduler will run in background
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user, exiting...")
    finally:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped.")


if __name__ == "__main__":
    main()

