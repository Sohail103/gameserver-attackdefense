"""
web_server.py

Flask web server for CTF game interface.
Provides scoreboard display and control endpoints.
"""

import logging
from flask import Flask, render_template_string, request, jsonify

from game_state import game_state, GameStatus, Team
from scanner import scanner
from flag_validator import flag_validator

logger = logging.getLogger("web_server")

app = Flask(__name__)


# HTML template for scoreboard
SCOREBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>CTF Scoreboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            margin: 0;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { text-align: center; color: #00ff00; text-shadow: 0 0 10px #00ff00; }
        .status {
            text-align: center;
            padding: 10px;
            margin: 20px 0;
            border: 2px solid #00ff00;
            background: #001a00;
        }
        .status.running { border-color: #00ff00; color: #00ff00; }
        .status.waiting { border-color: #ffaa00; color: #ffaa00; }
        .status.paused { border-color: #ff0000; color: #ff0000; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 0 20px rgba(0,255,0,0.2);
        }
        th, td {
            padding: 12px;
            text-align: left;
            border: 1px solid #00ff00;
        }
        th {
            background: #003300;
            color: #00ff00;
            font-weight: bold;
        }
        tr:nth-child(even) { background: #001100; }
        tr:hover { background: #002200; }
        .rank { font-weight: bold; font-size: 1.2em; }
        .score { font-weight: bold; color: #00ff00; }
        .controls {
            text-align: center;
            margin: 30px 0;
        }
        button {
            background: #003300;
            color: #00ff00;
            border: 2px solid #00ff00;
            padding: 10px 20px;
            margin: 0 5px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        button:hover {
            background: #00ff00;
            color: #000000;
        }
        .info { 
            text-align: center; 
            margin: 10px 0;
            color: #888;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚔️ CTF ATTACK/DEFENSE SCOREBOARD ⚔️</h1>
        
        <div class="status {{ game_info.status }}">
            <strong>Game Status:</strong> {{ game_info.status.upper() }}
            {% if game_info.start_time %}
            | Started: {{ game_info.start_time | timestamp }}
            {% endif %}
        </div>

        <table>
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>Team</th>
                    <th>IP</th>
                    <th>Score</th>
                    <th>Flags</th>
                    <th>Services Down</th>
                    <th>Last Scan</th>
                </tr>
            </thead>
            <tbody>
                {% for team in scoreboard %}
                <tr>
                    <td class="rank">#{{ team.rank }}</td>
                    <td>{{ team.name }}</td>
                    <td>{{ team.ip }}</td>
                    <td class="score">{{ team.score }}</td>
                    <td>{{ team.flags_captured }}</td>
                    <td>{{ team.services_down }}</td>
                    <td>{% if team.last_scan %}{{ team.last_scan | timestamp }}{% else %}Never{% endif %}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <div class="controls">
            <button onclick="controlGame('start')">▶️ Start Game</button>
            <button onclick="controlGame('pause')">⏸️ Pause Game</button>
            <button onclick="controlGame('stop')">⏹️ Stop Game</button>
            <button onclick="location.reload()">🔄 Refresh</button>
        </div>

        <div class="info">
            Scanner: {{ 'ACTIVE' if scanner_running else 'STOPPED' }} | 
            Scans: {{ game_info.scan_count }} | 
            Flags Submitted: {{ game_info.flag_submissions }}
        </div>
    </div>

    <script>
        function controlGame(action) {
            fetch('/api/control/' + action, { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    alert(data.message);
                    location.reload();
                })
                .catch(err => alert('Error: ' + err));
        }
    </script>
</body>
</html>
"""


@app.template_filter('timestamp')
def timestamp_filter(ts):
    """Format timestamp"""
    if ts is None:
        return "N/A"
    import datetime
    dt = datetime.datetime.fromtimestamp(ts)
    return dt.strftime('%H:%M:%S')


@app.route('/')
def index():
    """Main scoreboard page"""
    scoreboard = game_state.get_scoreboard()
    game_info = game_state.get_game_info()
    scanner_running = scanner.is_running()
    
    return render_template_string(
        SCOREBOARD_TEMPLATE,
        scoreboard=scoreboard,
        game_info=game_info,
        scanner_running=scanner_running
    )


@app.route('/api/scoreboard')
def api_scoreboard():
    """JSON scoreboard endpoint"""
    return jsonify({
        "scoreboard": game_state.get_scoreboard(),
        "game_info": game_state.get_game_info(),
        "scanner_running": scanner.is_running()
    })


@app.route('/api/control/<action>', methods=['POST'])
def control_game(action):
    """Control game state"""
    if action == 'start':
        game_state.set_status(GameStatus.RUNNING)
        if not scanner.is_running():
            scanner.start()
        return jsonify({"success": True, "message": "Game started!"})
    
    elif action == 'pause':
        game_state.set_status(GameStatus.PAUSED)
        return jsonify({"success": True, "message": "Game paused"})
    
    elif action == 'stop':
        game_state.set_status(GameStatus.FINISHED)
        scanner.stop()
        return jsonify({"success": True, "message": "Game stopped"})
    
    else:
        return jsonify({"success": False, "message": "Unknown action"}), 400


@app.route('/api/submit_flag', methods=['POST'])
def submit_flag():
    """
    Flag submission endpoint.
    POST body: {"team": "team-name", "flag": "FLAG{...}"}
    """
    data = request.get_json()
    
    if not data or 'team' not in data or 'flag' not in data:
        return jsonify({
            "success": False,
            "message": "Missing team or flag"
        }), 400
    
    team_name = data['team']
    flag = data['flag']
    
    # Check if team exists
    if not game_state.get_team(team_name):
        return jsonify({
            "success": False,
            "message": "Unknown team"
        }), 400
    
    # Check if game is running
    if game_state.get_status() != GameStatus.RUNNING:
        return jsonify({
            "success": False,
            "message": "Game is not running"
        }), 400
    
    # Validate flag
    is_valid, message, points = flag_validator.validate_submission(team_name, flag)
    
    return jsonify({
        "success": is_valid,
        "message": message,
        "points": points
    })


def run_web_server(host='0.0.0.0', port=5000, debug=False):
    """Run the Flask web server"""
    logger.info("Starting web server on %s:%d", host, port)
    app.run(host=host, port=port, debug=debug)
