"""
scanner.py

Service availability scanner using nmap.
Runs in background thread when game is active.
"""

import subprocess
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from apscheduler.schedulers.background import BackgroundScheduler
from typing import Dict, List

from game_state import game_state, GameStatus
from event_logger import log_service_down

logger = logging.getLogger("scanner")

NMAP_TIMEOUT = 8


class ServiceScanner:
    """Background service scanner"""
    
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self._running = False
        self._lock = threading.Lock()
    
    def start(self):
        """Start the scanner"""
        with self._lock:
            if self._running:
                logger.warning("Scanner already running")
                return
            
            self.scheduler.add_job(
                self._scan_all_teams,
                "interval",
                seconds=game_state.scan_interval
            )
            self.scheduler.start()
            self._running = True
            logger.info("Scanner started (interval=%ds)", game_state.scan_interval)
    
    def stop(self):
        """Stop the scanner"""
        with self._lock:
            if not self._running:
                return
            
            self.scheduler.shutdown(wait=False)
            self._running = False
            logger.info("Scanner stopped")
    
    def is_running(self) -> bool:
        """Check if scanner is running"""
        with self._lock:
            return self._running
    
    def _scan_all_teams(self):
        """Scan all teams (called by scheduler)"""
        # Only scan if game is running
        if game_state.get_status() != GameStatus.RUNNING:
            logger.debug("Game not running, skipping scan")
            return
        
        logger.debug("Starting scheduled scan of all teams")
        teams = game_state.get_all_teams()
        
        with ThreadPoolExecutor(max_workers=min(16, max(2, len(teams)))) as ex:
            futures = {
                ex.submit(self._check_team, name, team): name 
                for name, team in teams.items()
            }
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    logger.exception("Exception scanning team %s: %s", futures[fut], e)
    
    def _check_team(self, team_name: str, team):
        """Check a single team's services"""
        tcp_results = self._run_nmap(team.ip, team.expected_tcp_ports, udp=False)
        udp_results = {}
        
        if game_state.enable_udp and team.expected_udp_ports:
            udp_results = self._run_nmap(team.ip, team.expected_udp_ports, udp=True)
        
        # Determine missing services
        missing_tcp = [p for p, state in tcp_results.items() if state != "open"]
        missing_udp = [p for p, state in udp_results.items() if state != "open"]
        
        # Log each missing service
        for port in missing_tcp:
            log_service_down(
                team_name, f"TCP/{port}", game_state.penalty_per_port, 
                f"Port not open (state: {tcp_results.get(port, 'unknown')})"
            )
        for port in missing_udp:
            log_service_down(
                team_name, f"UDP/{port}", game_state.penalty_per_port,
                f"Port not open (state: {udp_results.get(port, 'unknown')})"
            )

        all_missing = missing_tcp + missing_udp
        penalty = len(all_missing) * game_state.penalty_per_port
        
        # Record results
        game_state.record_scan_result(team_name, all_missing, penalty)
        
        logger.info(
            "Scanned %s (%s): missing_tcp=%s missing_udp=%s penalty=%d",
            team_name, team.ip, missing_tcp, missing_udp, penalty
        )
    
    def _run_nmap(self, ip: str, ports: List[int], udp: bool = False) -> Dict[int, str]:
        """Run nmap on a host for provided ports"""
        if not ports:
            return {}
        
        ports_str = ",".join(str(p) for p in ports)
        cmd = ["nmap", "-Pn", "-p", ports_str, "-oG", "-", ip]
        if udp:
            cmd.insert(1, "-sU")
        
        logger.debug("Running nmap: %s", " ".join(cmd))
        
        try:
            out = subprocess.check_output(
                cmd, 
                stderr=subprocess.STDOUT, 
                timeout=NMAP_TIMEOUT, 
                text=True
            )
        except subprocess.CalledProcessError as e:
            logger.error("nmap failed: %s", e.output or str(e))
            return {p: "unknown" for p in ports}
        except subprocess.TimeoutExpired:
            logger.error("nmap timed out for %s:%s", ip, ports_str)
            return {p: "unknown" for p in ports}
        except FileNotFoundError:
            logger.error("nmap binary not found")
            return {p: "unknown" for p in ports}
        
        # Parse greppable output
        results = {p: "closed" for p in ports}
        for line in out.splitlines():
            line = line.strip()
            if not line or not line.startswith("Host:"):
                continue
            
            if "Ports:" not in line:
                continue
            
            parts = line.split("Ports:", 1)[1].strip()
            for segment in parts.split(","):
                seg = segment.strip()
                if not seg:
                    continue
                
                seg_parts = seg.split("/")
                try:
                    port = int(seg_parts[0])
                    state = seg_parts[1]
                except Exception:
                    continue
                
                if port in results:
                    results[port] = state
        
        return results


# Global scanner instance
scanner = ServiceScanner()
