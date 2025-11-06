"""""
flag_validator.py

Flag generation and validation logic for CTF submissions.
Each service on each team has one active flag at a time.
"""

import logging
import hashlib
import secrets
import time
from typing import Optional, Tuple, Dict

from game_state import game_state

logger = logging.getLogger("flag_validator")


class FlagValidator:
    """Manages flag generation and validation"""
    
    def __init__(self):
        # Store active flags: (team_name, service_name) -> (flag_string, timestamp)
        self._active_flags: Dict[tuple, tuple] = {}
        # Reverse lookup: flag_string -> (team_name, service_name)
        self._flag_lookup: Dict[str, tuple] = {}
    
    def generate_flag(self, team_name: str, service_name: str) -> Tuple[bool, str, str]:
        """
        Generate a unique flag for a team's service.
        Replaces any existing flag for that team+service combination.
        
        Args:
            team_name: Name of the team 
            service_name: Name of the service requesting the flag
            
        Returns:
            (success, flag_string, message)
        """
        # Verify team exists
        if not game_state.get_team(team_name):
            logger.warning("Flag generation requested for unknown team: %s", team_name)
            return False, "", "Unknown team"
        
        # Generate a cryptographically secure random flag
        random_data = secrets.token_hex(16)
        timestamp = int(time.time())
        
        # Create flag in format: FLAG{team_service_randomhex}
        flag = f"FLAG{{{team_name}_{service_name}_{random_data}}}"
        
        key = (team_name, service_name)
        
        # Remove old flag if it exists
        if key in self._active_flags:
            old_flag = self._active_flags[key][0]
            if old_flag in self._flag_lookup:
                del self._flag_lookup[old_flag]
            logger.info("Replaced flag for %s/%s", team_name, service_name)
        
        # Store new flag
        self._active_flags[key] = (flag, timestamp)
        self._flag_lookup[flag] = (team_name, service_name)
        
        logger.info("Generated flag for team=%s service=%s: %s", 
                   team_name, service_name, flag)
        
        return True, flag, "Flag generated successfully"
    
    def validate_submission(
        self, 
        attacker_team: str, 
        flag: str
    ) -> Tuple[bool, str, int]:
        """
        Validate a flag submission.
        
        Args:
            attacker_team: Name of the team submitting the flag
            flag: The flag string they captured
            
        Returns:
            (is_valid, message, points_awarded)
        """
        # Check if attacking team exists
        if not game_state.get_team(attacker_team):
            logger.info("Unknown team tried to submit flag: %s", attacker_team)
            return False, "Unknown team", 0
        
        # Check if flag exists in our lookup
        if flag not in self._flag_lookup:
            logger.info("Invalid flag submitted by %s: %s", attacker_team, flag)
            return False, "Invalid or expired flag", 0
        
        victim_team, service_name = self._flag_lookup[flag]
        
        # Check if team is attacking themselves
        if attacker_team == victim_team:
            logger.info("Team %s tried to submit their own flag", attacker_team)
            return False, "Cannot submit your own flag", 0
        
        # Valid flag!
        points = game_state.flag_points
        game_state.record_flag_submission(
            attacker=attacker_team,
            victim=victim_team,
            flag=flag,
            points=points,
            valid=True
        )
        
        # Remove the captured flag (it can only be submitted once)
        key = (victim_team, service_name)
        if key in self._active_flags:
            del self._active_flags[key]
        del self._flag_lookup[flag]
        
        logger.info(
            "Valid flag submitted: %s captured %s's %s service (+%d points)",
            attacker_team, victim_team, service_name, points
        )
        
        return True, f"Valid flag! Captured {victim_team}'s {service_name} service", points
    
    def get_active_flag_count(self) -> int:
        """Get count of active flags"""
        return len(self._active_flags)
    
    def get_team_flags(self, team_name: str) -> Dict[str, str]:
        """
        Get all active flags for a specific team (for debugging/admin).
        Returns dict: service_name -> flag_string
        """
        result = {}
        for (t_name, service), (flag, _) in self._active_flags.items():
            if t_name == team_name:
                result[service] = flag
        return result
    
    def cleanup_old_flags(self, max_age_seconds: int = 3600):
        """
        Optional: Remove flags older than max_age (default 1 hour).
        Useful for long-running games to prevent stale flags.
        """
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
