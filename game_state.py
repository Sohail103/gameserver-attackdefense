"""
game_state.py

Shared state for the CTF game server.
Thread-safe management of teams, scores, and game status.
"""

import threading
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum
import json
import secrets


class GameStatus(Enum):
    WAITING = "waiting"
    RUNNING = "running"
    PAUSED = "paused"
    FINISHED = "finished"


@dataclass
class Team:
    name: str
    ip: str
    token: str
    expected_tcp_ports: List[int]
    expected_udp_ports: List[int] = field(default_factory=list)
    score: int = 1000
    flags_captured: int = 0
    services_down: List[int] = field(default_factory=list)
    consecutive_failures: Dict[int, int] = field(default_factory=dict)
    last_scan: Optional[float] = None
    scanning_paused: bool = False


class GameState:
    """Thread-safe game state manager"""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._teams: Dict[str, Team] = {}
        self._status = GameStatus.WAITING
        self._game_start_time: Optional[float] = None
        self._scan_history: List[Dict] = []
        self._flag_history: List[Dict] = []
        
        # Configuration
        self.penalty_per_port = 10
        self.flag_points = 50
        self.flag_stolen_penalty = 25
        self.scan_interval = 10
        self.enable_udp = False
    
    def add_team(self, team: Team):
        """Add a team to the game"""
        with self._lock:
            self._teams[team.name] = team
    
    def get_team(self, name: str) -> Optional[Team]:
        """Get a team by name"""
        with self._lock:
            return self._teams.get(name)
    
    def get_all_teams(self) -> Dict[str, Team]:
        """Get all teams (returns a copy)"""
        with self._lock:
            return dict(self._teams)
    
    def update_team_score(self, team_name: str, delta: int):
        """Update a team's score by delta (can be negative)"""
        with self._lock:
            if team_name in self._teams:
                self._teams[team_name].score = max(0, self._teams[team_name].score + delta)
    
    def record_scan_result(self, team_name: str, missing_ports: List[int], penalty: int):
        """Record the results of a service scan"""
        with self._lock:
            if team_name in self._teams:
                team = self._teams[team_name]
                team.services_down = missing_ports
                team.last_scan = time.time()
                team.score = max(0, team.score - penalty)
                
                self._scan_history.append({
                    "timestamp": time.time(),
                    "team": team_name,
                    "missing_ports": missing_ports,
                    "penalty": penalty,
                    "score": team.score
                })
    
    def record_flag_submission(self, attacker: Team, victim: Team, flag: str, points: int, valid: bool):
        """Record a flag submission attempt"""
        with self._lock:
            self._flag_history.append({
                "timestamp": time.time(),
                "attacker": attacker.name,
                "victim": victim.name,
                "flag": flag,
                "points": points,
                "valid": valid
            })
            
            if valid:
                attacker.score += points
                attacker.flags_captured += 1
                victim.score = max(0, victim.score - self.flag_stolen_penalty)
    
    def get_status(self) -> GameStatus:
        """Get current game status"""
        with self._lock:
            return self._status
    
    def set_status(self, status: GameStatus):
        """Set game status"""
        with self._lock:
            self._status = status
            if status == GameStatus.RUNNING and self._game_start_time is None:
                self._game_start_time = time.time()
    
    def get_scoreboard(self) -> List[Dict]:
        """Get scoreboard sorted by score"""
        with self._lock:
            teams = sorted(
                self._teams.values(),
                key=lambda t: t.score,
                reverse=True
            )
            return [
                {
                    "rank": i + 1,
                    "name": t.name,
                    "ip": t.ip,
                    "token": t.token,
                    "score": t.score,
                    "flags_captured": t.flags_captured,
                    "services_down": len(t.services_down),
                    "last_scan": t.last_scan,
                    "scanning_paused": t.scanning_paused,
                    "expected_tcp_ports": t.expected_tcp_ports
                }
                for i, t in enumerate(teams)
            ]
    
    def get_game_info(self) -> Dict:
        """Get overall game information"""
        with self._lock:
            return {
                "status": self._status.value,
                "start_time": self._game_start_time,
                "team_count": len(self._teams),
                "scan_count": len(self._scan_history),
                "flag_submissions": len(self._flag_history)
            }

    def get_recent_events(self, limit: int = 15) -> List[Dict]:
        """Get the most recent valid flag captures."""
        with self._lock:
            # Filter for valid submissions and get a copy
            valid_submissions = [event for event in self._flag_history if event["valid"]]
            # Return the last `limit` events, reversed so newest is first
            return valid_submissions[-limit:][::-1]

    def load_teams_from_json(self, file_path: str = 'teams.json'):
        """Load team data from a JSON file"""
        try:
            with open(file_path, 'r') as f:
                teams_data = json.load(f)
            with self._lock:
                for team_data in teams_data:
                    if 'ports' in team_data:
                        team_data['expected_tcp_ports'] = team_data.pop('ports')
                    if 'token' not in team_data:
                        team_data['token'] = f"token-{team_data['name']}-{secrets.token_hex(8)}"
                    team = Team(**team_data)
                    self._teams[team.name] = team
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading teams from {file_path}: {e}")

    def save_teams_to_json(self, file_path: str = 'teams.json'):
        """Save current team data to a JSON file"""
        with self._lock:
            teams_data = [asdict(team) for team in self._teams.values()]
            with open(file_path, 'w') as f:
                json.dump(teams_data, f, indent=4)

    def add_team(self, team: Team):
        """Add a new team and save to JSON"""
        with self._lock:
            if team.name in self._teams:
                raise ValueError(f"Team '{team.name}' already exists.")
            self._teams[team.name] = team
        self.save_teams_to_json()

    def update_team(self, team_name: str, updates: Dict):
        """Update a team's attributes and save to JSON"""
        with self._lock:
            if team_name not in self._teams:
                raise ValueError(f"Team '{team_name}' not found.")
            team = self._teams[team_name]
            for key, value in updates.items():
                if hasattr(team, key):
                    setattr(team, key, value)
            self._teams[team_name] = team
        self.save_teams_to_json()

    def delete_team(self, team_name: str):
        """Delete a team and save to JSON"""
        with self._lock:
            if team_name not in self._teams:
                raise ValueError(f"Team '{team_name}' not found.")
            del self._teams[team_name]
        self.save_teams_to_json()

    def reset_game_state(self):
        """Reset the game to the initial state"""
        with self._lock:
            for team in self._teams.values():
                team.score = 1000
                team.scanning_paused = False
                team.last_scan = None
                team.services_down = []
                team.consecutive_failures = {}
        self.save_teams_to_json()


# Global game state instance
game_state = GameState()
