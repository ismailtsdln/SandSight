from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional
import time
import docker # type: ignore
from rich.console import Console

console = Console()

class BaseSandbox(ABC):
    """
    Abstract base class for sandbox backends.
    """
    def __init__(self, working_dir: Path):
        self.working_dir = working_dir
        if not self.working_dir.exists():
            self.working_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def start(self):
        """Start the sandbox environment."""
        pass

    @abstractmethod
    def stop(self):
        """Stop and cleanup the sandbox environment."""
        pass

    @abstractmethod
    def run_sample(self, file_path: Path, timeout: int = 60, allow_network: bool = False, dump_memory: bool = False) -> Dict[str, Any]:
        """Run a sample in the sandbox."""
        pass

class DockerSandbox(BaseSandbox):
    """
    Docker-based sandbox implementation.
    """
    def __init__(self, working_dir: Path, image_name: str = "sandsight-sandbox:latest"):
        super().__init__(working_dir)
        self.image_name = image_name
        self.client = docker.from_env()
        self.container = None

    def start(self):
        # Docker containers are usually started on demand in run_sample, 
        # but we could spin up a warm container here.
        # For now, we'll keep it simple.
        pass

    def stop(self):
        if self.container:
            try:
                self.container.stop()
                self.container.remove()
                console.print("[dim]Container stopped and removed.[/dim]")
            except Exception as e:
                console.print(f"[red]Error stopping container: {e}[/red]")

    def run_sample(self, file_path: Path, timeout: int = 60, allow_network: bool = False, dump_memory: bool = False) -> Dict[str, Any]:
        """
        Run a sample in a Docker container.
        """
        results = {
            "success": False,
            "duration": 0,
            "exit_code": None,
            "execution_logs": "",
            "strace_log": "",
            "pcap_data": None,
            "memory_dump": None,
            "error": None
        }
        
        try:
            # Check if image exists, pull if not (mock logic mostly for now, assumes local image or public)
            try:
                self.client.images.get(self.image_name)
            except docker.errors.ImageNotFound:
                 console.print(f"[yellow]Image {self.image_name} not found, attempting pull...[/yellow]")
                 # self.client.images.pull(self.image_name) # Commented out to avoid random pulling
                 results["error"] = f"Image {self.image_name} not found. Please build it first."
                 return results

            start_time = time.time()
            
            # Run container with strace and optional tcpdump
            # We wrap the command to handle tcpdump in background if needed
            wrapper = []
            if allow_network:
                wrapper.append("tcpdump -i any -w /tmp/capture.pcap & sleep 2")
            
            # strace command
            strace_cmd = f"strace -f -e trace=file,network,process -o /tmp/strace.log /sample/{file_path.name}"
            
            # memory dump command (gcore needs a pid, we can try to guess or use a script)
            # For simplicity, we'll try to gcore the process if it's still running after a bit
            # or just at the end if we can catch it. 
            # A better way is using a separate exec but we'll try to keep it contained.
            
            cmd = f"/bin/sh -c 'chmod +x /sample/{file_path.name} && {' && '.join(wrapper) + ' && ' if wrapper else ''} {strace_cmd}'"
            
            self.container = self.client.containers.run(
                self.image_name,
                command=cmd,
                volumes={str(file_path.parent.absolute()): {'bind': '/sample', 'mode': 'ro'}},
                detach=True,
                network_disabled=not allow_network, 
                mem_limit='512m',
                cap_add=['SYS_PTRACE', 'NET_ADMIN'], # NET_ADMIN for tcpdump
                security_opt=['seccomp:unconfined'],
            )
            
            # Wait for finish or timeout
            try:
                result = self.container.wait(timeout=timeout)
                results["exit_code"] = result.get('StatusCode')
            except Exception as e: # Timeout
                # If it's a timeout, maybe we can still try to dump memory before killing?
                if dump_memory:
                    try:
                        # Try to find the process pid in container
                        exec_res = self.container.exec_run("pgrep -f " + file_path.name)
                        pid = exec_res.output.decode().strip()
                        if pid:
                            self.container.exec_run(f"gcore -o /tmp/memdump {pid}")
                    except:
                        pass
                
                self.container.kill()
                results["error"] = "Execution timed out"
            
            results["duration"] = time.time() - start_time
            
            # Capture logs
            logs = self.container.logs(stdout=True, stderr=True)
            results["execution_logs"] = logs.decode('utf-8', errors='replace')
            
            # Capture artifacts from container
            self._capture_artifacts(results, allow_network, dump_memory)
                
        except Exception as e:
            results["error"] = str(e)
        finally:
            if self.container:
                try:
                    self.container.remove(force=True)
                except:
                    pass
            self.container = None
            
        return results

    def _capture_artifacts(self, results, allow_network, dump_memory):
        """Helper to pull files from container."""
        import tarfile
        import io

        def get_file(path):
            try:
                bits, stat = self.container.get_archive(path)
                file_obj = io.BytesIO()
                for chunk in bits:
                    file_obj.write(chunk)
                file_obj.seek(0)
                with tarfile.open(fileobj=file_obj) as tar:
                    # container.get_archive(path) returns a tar containing 'path'
                    member_name = Path(path).name
                    member = tar.getmember(member_name)
                    return tar.extractfile(member).read()
            except:
                return None

        # strace
        strace_data = get_file('/tmp/strace.log')
        if strace_data:
            results["strace_log"] = strace_data.decode('utf-8', errors='replace')

        # pcap
        if allow_network:
            results["pcap_data"] = get_file('/tmp/capture.pcap')

        # memory dump
        if dump_memory:
            # gcore output usually has .<pid> suffix if we didn't specify exactly
            # but we'll check common names
            mem_data = get_file('/tmp/memdump')
            if mem_data:
                results["memory_dump"] = mem_data
