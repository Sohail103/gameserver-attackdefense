"""
config.example.py

Example configuration file for CTF game server.
Copy this to config.py and customize for your CTF.
"""

from game_state import Team

# Game configuration
SCAN_INTERVAL = 10  # seconds between scans
PENALTY_PER_PORT = 10  # points deducted per missing service
FLAG_POINTS = 50  # points for capturing a flag
ENABLE_UDP = False  # Enable UDP scanning (requires root)

# Web server configuration
WEB_HOST = '0.0.0.0'
WEB_PORT = 5000

# Teams configuration
TEAMS = [
    Team(
        name="team-alpha",
        ip="10.0.2.10",
        expected_tcp_ports=[22, 80, 5000],
        expected_udp_ports=[],
        score=1000
    ),
    Team(
        name="team-bravo",
        ip="10.0.2.11",
        expected_tcp_ports=[22, 7000, 8081],
        expected_udp_ports=[],
        score=1000
    ),
    Team(
        name="team-charlie",
        ip="10.0.2.12",
        expected_tcp_ports=[22, 3000, 8080],
        expected_udp_ports=[],
        score=1000
    ),
    # Add more teams as needed
]
