"""
flag_validator.py

Flag generation and validation logic for CTF submissions.
Each service on each team has one active flag at a time.
"""

import logging
import secrets
import time
from typing import Tuple, Dict, Set

from game_state import game_state
from event_logger import log_flag_submission

logger = logging.getLogger("flag_validator")


class FlagValidator:
    """Manages flag generation and validation"""
    
    def __init__(self):
        # Store active flags: (team_name, service_name) -> (flag_string, timestamp)
        self._active_flags: Dict[tuple, tuple] = {}
        # Reverse lookup: flag_string -> (team_name, service_name)
        self._flag_lookup: Dict[str, tuple] = {}
        # Track submissions to prevent duplicates per team/ip
        # Structure: {ip_or_team: set_of_flags_submitted}
        self._submissions: Dict[str, Set[str]] = {}

    def generate_flag(self, team_name: str, service_name: str) -> Tuple[bool, str, str]:
        """Generate a unique flag for a team's service."""
        if not game_state.get_team(team_name):
            logger.warning("Flag generation requested for unknown team: %s", team_name)
            return False, "", "Unknown team"
        
        random_data = secrets.token_hex(16)
        timestamp = int(time.time())
        flag = f"FLAG{{{team_name}_{service_name}_{random_data}}}"
        key = (team_name, service_name)
        
        if key in self._active_flags:
            old_flag = self._active_flags[key][0]
            if old_flag in self._flag_lookup:
                del self._flag_lookup[old_flag]
            logger.info("Replaced flag for %s/%s", team_name, service_name)
        
        self._active_flags[key] = (flag, timestamp)
        self._flag_lookup[flag] = (team_name, service_name)
        
        logger.info("Generated flag for team=%s service=%s: %s", team_name, service_name, flag)
        return True, flag, "Flag generated successfully"

    def validate_submission(self, attacker_ip: str, flag: str) -> Tuple[bool, str, int]:
        """
        Validate a flag submission.

        Args:
            attacker_ip: IP address of the team submitting the flag (used to infer team)
            flag: The flag string they captured
            
        Returns:
            (is_valid, message, points_awarded)
        """
        # Map IP to team
        attacker_team = None
        for team in game_state.get_all_teams().values():
            if team.ip == attacker_ip:
                attacker_team = team
                break

        if not attacker_team:
            message = "Unknown team (IP not registered)"
            logger.info("Unknown IP %s tried to submit flag %s", attacker_ip, flag)
            log_flag_submission(attacker_ip, None, flag, message, is_valid=False)
            return False, message, 0
        
        # Check if flag exists
        if flag not in self._flag_lookup:
            message = "Invalid or expired flag"
            logger.info("Invalid flag submitted by %s (%s): %s", attacker_team, attacker_ip, flag)
            log_flag_submission(attacker_ip, attacker_team, flag, message, is_valid=False)
            return False, message, 0
        
        victim_team_name, service_name = self._flag_lookup[flag]
        victim_team = game_state.get_team(victim_team_name)

        # Prevent self-submission
        if attacker_team == victim_team:
            message = "Cannot submit your own flag"
            logger.info("Team %s (%s) tried to submit their own flag", attacker_team.name, attacker_ip)
            log_flag_submission(attacker_ip, attacker_team.name, flag, message, is_valid=False)
            return False, message, 0
        
        # Prevent duplicate submissions by same IP/team
        if attacker_ip not in self._submissions:
            self._submissions[attacker_ip] = set()
        
        if flag in self._submissions[attacker_ip]:
            message = "You have already submitted this flag"
            logger.info("Duplicate flag submission blocked: %s (%s) tried %s again", attacker_team.name, attacker_ip, flag)
            log_flag_submission(attacker_ip, attacker_team.name, flag, message, is_valid=False)
            return False, message, 0
        
        # Record successful submission
        self._submissions[attacker_ip].add(flag)
        
        points = game_state.flag_points
        game_state.record_flag_submission(
            attacker=attacker_team,
            victim=victim_team,
            flag=flag,
            points=points,
            valid=True
        )
        
        logger.info(
            "Valid flag submitted: %s (%s) captured %s's %s service (+%d points)",
            attacker_team.name, attacker_ip, victim_team.name, service_name, points
        )
        
        message = f"Valid flag! Captured {victim_team.name}'s {service_name} service"
        log_flag_submission(attacker_ip, attacker_team.name, flag, message, is_valid=True)
        return True, message, points

    def get_active_flag_count(self) -> int:
        return len(self._active_flags)
    
    def get_team_flags(self, team_name: str) -> Dict[str, str]:
        result = {}
        for (t_name, service), (flag, _) in self._active_flags.items():
            if t_name == team_name:
                result[service] = flag
        return result
    
    def cleanup_old_flags(self, max_age_seconds: int = 3600):
        current_time = time.time()
        to_remove = []
        
        for key, (flag, timestamp) in self._active_flags.items():
            if current_time - timestamp > max_age_seconds:
                to_remove.append((key, flag))
        
        for key, flag in to_remove:
            del self._active_flags[key]
            if flag in self._flag_lookup:
                del self._flag_lookup[flag]
        
        if to_remove:
            logger.info("Cleaned up %d old flags", len(to_remove))


# Global flag validator instance
flag_validator = FlagValidator()
