import platform
import subprocess
import shutil
import os
import re
import socket
import threading
import signal
import time

active_processes = {}

def validate_domain(domain: str) -> bool:
    pattern = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    return bool(re.match(pattern, domain))

def validate_target(target: str) -> bool:
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ip_pattern, target) or validate_domain(target))

def is_tool_available(name: str) -> bool:
    if platform.system() == "Windows":
        if not shutil.which("wsl"):
            return False
        try:
            result = subprocess.run(["wsl", "which", name], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            try:
                result = subprocess.run(["wsl", name, "--help"], capture_output=True, text=True, timeout=5)
                return result.returncode in (0, 1)
            except:
                return False
    else:
        return shutil.which(name) is not None

def scan_port(target: str, port: int, timeout: float = 3.0, retries: int = 2):
    try:
        addrinfo = socket.getaddrinfo(target, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return port, False

    for _ in range(retries):
        for family, socktype, proto, _, sockaddr in addrinfo:
            try:
                with socket.socket(family, socktype, proto) as s:
                    s.settimeout(timeout)
                    if s.connect_ex(sockaddr) == 0:
                        return port, True
            except:
                continue
    return port, False

def run_cmd_with_cancel(cmd: list, timeout: int = 300, is_cancelled=lambda: False) -> subprocess.CompletedProcess:
    thread_id = threading.get_ident()

    try:
        is_windows = platform.system() == "Windows"
        use_shell = is_windows

        if is_windows:
            cmd = ["wsl", "sudo"] + cmd if cmd[0] == "nmap" else ["wsl"] + cmd

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=use_shell
        )

        active_processes[thread_id]['process'] = process

        def monitor():
            start = time.time()
            while process.poll() is None and (time.time() - start) < timeout:
                if is_cancelled() or active_processes[thread_id].get('cancelled', False):
                    try:
                        process.kill()
                    except:
                        pass
                    return
                time.sleep(0.5)
            if process.poll() is None:
                process.kill()

        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.start()

        stdout, stderr = process.communicate()
        monitor_thread.join()

        return subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, "", f"Erro inesperado: {str(e)}\nComando: {cmd}")
    finally:
        if thread_id in active_processes:
            del active_processes[thread_id]

def fast_port_scan(target: str, start=1, end=1024, threads=100, is_cancelled=None):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, target, port, timeout=1.0, retries=1): port
            for port in range(start, end + 1)
        }
        for future in as_completed(futures):
            if is_cancelled and is_cancelled():
                break
            port, is_open = future.result()
            if is_open:
                open_ports.append(str(port))
    return open_ports

def register_scan(scan_type: str):
    thread_id = threading.get_ident()
    active_processes[thread_id] = {'cancelled': False, 'type': scan_type}
    return thread_id

def is_scan_cancelled(thread_id=None):
    if thread_id is None:
        thread_id = threading.get_ident()
    return active_processes.get(thread_id, {}).get('cancelled', False)

def cancel_scan(thread_id=None):
    if thread_id is None:
        thread_id = threading.get_ident()
    if thread_id in active_processes:
        active_processes[thread_id]['cancelled'] = True
        process = active_processes[thread_id].get('process')
        if process:
            try:
                if platform.system() == "Windows":
                    process.kill()
                else:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except:
                try:
                    process.kill()
                except:
                    pass
        return True
    return False

def cleanup_scan(thread_id=None):
    if thread_id is None:
        thread_id = threading.get_ident()
    if thread_id in active_processes:
        del active_processes[thread_id]
