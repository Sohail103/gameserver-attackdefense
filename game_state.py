"""
game_state.py

Shared state for the CTF game server.
Thread-safe management of teams, scores, and game status.
"""

import threading
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class GameStatus(Enum):
    WAITING = "waiting"
    RUNNING = "running"
    PAUSED = "paused"
    FINISHED = "finished"


@dataclass
class Team:
    name: str
    ip: str
    expected_tcp_ports: List[int]
    expected_udp_ports: List[int] = field(default_factory=list)
    score: int = 1000
    flags_captured: int = 0
    services_down: List[int] = field(default_factory=list)
    last_scan: Optional[float] = None


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
    
    def record_flag_submission(self, attacker: str, victim: str, flag: str, points: int, valid: bool):
        """Record a flag submission attempt"""
        with self._lock:
            self._flag_history.append({
                "timestamp": time.time(),
                "attacker": attacker,
                "victim": victim,
                "flag": flag,
                "points": points,
                "valid": valid
            })
            
            if valid and attacker in self._teams:
                self._teams[attacker].score += points
                self._teams[attacker].flags_captured += 1
    
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
                    "score": t.score,
                    "flags_captured": t.flags_captured,
                    "services_down": len(t.services_down),
                    "last_scan": t.last_scan
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


# Global game state instance
game_state = GameState()
