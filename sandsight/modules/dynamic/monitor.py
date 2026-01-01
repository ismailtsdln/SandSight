import re
from typing import Dict, Any, List
import time

class Monitor:
    """
    Monitor module for dynamic analysis.
    Aggregates logs, processes strace output, and analyzes network traffic.
    """
    def __init__(self):
        self.logs = []
        self.events = []

    def log_event(self, event_type: str, message: str):
        timestamp = time.time()
        event = {
            "timestamp": timestamp,
            "type": event_type,
            "message": message
        }
        self.events.append(event)
        
    def parse_system_logs(self, raw_logs: str) -> List[Dict[str, Any]]:
        """
        Parse raw stdout/stderr from the sandbox.
        """
        parsed = []
        for line in raw_logs.splitlines():
            if line.strip():
                parsed.append({
                    "raw": line.strip()
                })
        return parsed

    def parse_strace(self, strace_log: str) -> Dict[str, Any]:
        """
        Extract behavioral patterns from strace output.
        """
        results = {
            "files_accessed": set(),
            "network_connections": set(),
            "processes_spawned": set(),
            "suspicious_calls": []
        }

        # Regex for common syscalls
        # open/openat(AT_FDCWD, "/path/to/file", ...)
        file_re = re.compile(r'(?:open|openat)\(.*?,\s*"([^"]+)"')
        
        # connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.1.1.1")}, 16)
        connect_re = re.compile(r'connect\(.*?sin_addr=inet_addr\("([^"]+)"\)')
        
        # execve("/bin/sh", ["/bin/sh", "-c", "..."], ...)
        exec_re = re.compile(r'execve\("([^"]+)"')

        for line in strace_log.splitlines():
            # File access
            file_match = file_re.search(line)
            if file_match:
                path = file_match.group(1)
                if not path.startswith('/lib') and not path.startswith('/usr/lib') and not path.startswith('/etc/ld.so'):
                    results["files_accessed"].add(path)

            # Network
            net_match = connect_re.search(line)
            if net_match:
                results["network_connections"].add(net_match.group(1))

            # Processes
            proc_match = exec_re.search(line)
            if proc_match:
                results["processes_spawned"].add(proc_match.group(1))
            
            # Suspicious
            if "ptrace" in line:
                results["suspicious_calls"].append("Process attempted anti-debugging (ptrace)")

        # Convert sets to sorted lists for JSON serialization
        results["files_accessed"] = sorted(list(results["files_accessed"]))
        results["network_connections"] = sorted(list(results["network_connections"]))
        results["processes_spawned"] = sorted(list(results["processes_spawned"]))
        
        return results
