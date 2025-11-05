"""
flag_validator.py

Flag validation logic for CTF submissions.
"""

import logging
import hashlib
import time
from typing import Optional, Tuple

from game_state import game_state

logger = logging.getLogger("flag_validator")


class FlagValidator:
    """Validates flag submissions"""
    
    def __init__(self):
        # Store generated flags: flag_string -> (victim_team, timestamp)
        self._active_flags = {}
        self._flag_lifetime = 300  # 5 minutes
    
    def generate_flag(self, victim_team: str) -> str:
        """
        Generate a unique flag for a victim team.
        In a real CTF, you'd deploy this flag to the victim's service.
        """
        timestamp = int(time.time())
        data = f"{victim_team}:{timestamp}".encode()
        flag_hash = hashlib.sha256(data).hexdigest()[:16]
        flag = f"FLAG{{{flag_hash}}}"
        
        self._active_flags[flag] = (victim_team, timestamp)
        logger.info("Generated flag %s for team %s", flag, victim_team)
        return flag
    
    def validate_submission(
        self, 
        attacker_team: str, 
        flag: str
    ) -> Tuple[bool, str, int]:
        """
        Validate a flag submission.
        
        Returns:
            (is_valid, message, points_awarded)
        """
        # Check if flag exists
        if flag not in self._active_flags:
            logger.info("Invalid flag submitted by %s: %s", attacker_team, flag)
            return False, "Invalid flag", 0
        
        victim_team, flag_timestamp = self._active_flags[flag]
        
        # Check if flag has expired
        if time.time() - flag_timestamp > self._flag_lifetime:
            logger.info("Expired flag submitted by %s", attacker_team)
            return False, "Flag has expired", 0
        
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
        
        # Remove flag so it can't be resubmitted
        del self._active_flags[flag]
        
        logger.info(
            "Valid flag submitted: %s captured flag from %s (+%d points)",
            attacker_team, victim_team, points
        )
        
        return True, f"Valid flag! Captured from {victim_team}", points
    
    def cleanup_expired_flags(self):
        """Remove expired flags from memory"""
        current_time = time.time()
        expired = [
            flag for flag, (_, ts) in self._active_flags.items()
            if current_time - ts > self._flag_lifetime
        ]
        
        for flag in expired:
            del self._active_flags[flag]
        
        if expired:
            logger.info("Cleaned up %d expired flags", len(expired))
    
    def get_active_flag_count(self) -> int:
        """Get count of active flags"""
        return len(self._active_flags)


# Global flag validator instance
flag_validator = FlagValidator()
