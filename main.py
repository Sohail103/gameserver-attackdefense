#!/usr/bin/env python3
"""
main.py

Main entry point for CTF Attack/Defense game server.
Orchestrates all components.
"""

import logging
import argparse

from game_state import game_state, Team
from web_server import run_web_server

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger("main")


def setup_teams():
    """Initialize teams - customize this for your CTF"""
    teams = [
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
    ]
    
    for team in teams:
        game_state.add_team(team)
        logger.info("Added team: %s (%s)", team.name, team.ip)


def main():
    parser = argparse.ArgumentParser(description="CTF Attack/Defense Game Server")
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host to bind web server (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port for web server (default: 5000)'
    )
    parser.add_argument(
        '--scan-interval',
        type=int,
        default=10,
        help='Service scan interval in seconds (default: 10)'
    )
    parser.add_argument(
        '--penalty',
        type=int,
        default=10,
        help='Penalty points per missing service (default: 10)'
    )
    parser.add_argument(
        '--flag-points',
        type=int,
        default=50,
        help='Points awarded for valid flag (default: 50)'
    )
    parser.add_argument(
        '--enable-udp',
        action='store_true',
        help='Enable UDP port scanning (requires root)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    
    args = parser.parse_args()
    
    # Configure game state
    game_state.scan_interval = args.scan_interval
    game_state.penalty_per_port = args.penalty
    game_state.flag_points = args.flag_points
    game_state.enable_udp = args.enable_udp
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info("=" * 60)
    logger.info("CTF Attack/Defense Game Server")
    logger.info("=" * 60)
    logger.info("Configuration:")
    logger.info("  Web Server: http://%s:%d", args.host, args.port)
    logger.info("  Scan Interval: %d seconds", args.scan_interval)
    logger.info("  Penalty per port: %d points", args.penalty)
    logger.info("  Flag points: %d points", args.flag_points)
    logger.info("  UDP scanning: %s", "enabled" if args.enable_udp else "disabled")
    logger.info("=" * 60)
    
    # Setup teams
    setup_teams()
    logger.info("Loaded %d teams", len(game_state.get_all_teams()))
    
    # Print instructions
    print("\n" + "=" * 60)
    print("🎮 CTF Game Server Ready!")
    print("=" * 60)
    print(f"📊 Scoreboard: http://{args.host}:{args.port}")
    print(f"🚀 To start scanning, click 'Start Game' on the web interface")
    print(f"🏁 Flag submission: POST to http://{args.host}:{args.port}/api/submit_flag")
    print("   Example: curl -X POST http://localhost:5000/api/submit_flag \\")
    print('            -H "Content-Type: application/json" \\')
    print('            -d \'{"team": "team-alpha", "flag": "FLAG{...}"}\'')
    print("=" * 60)
    print("\nPress Ctrl+C to stop the server\n")
    
    # Run web server (blocks)
    try:
        run_web_server(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        logger.info("\nShutdown requested by user")
    finally:
        # Cleanup
        from scanner import scanner
        if scanner.is_running():
            scanner.stop()
        logger.info("Server stopped")


if __name__ == "__main__":
    main()
