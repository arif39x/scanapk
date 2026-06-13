import os
import shutil
import subprocess
import sys
import time

MONITOR_DIR = os.path.expanduser("~/scanapk_monitor")
_mitm_proc = None


def _adb():
    adb = shutil.which("adb")
    if not adb:
        adb = os.path.expanduser("~/Android/Sdk/platform-tools/adb")
    return adb


def _run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def install():
    """Install mitmproxy Python package."""
    if shutil.which("mitmdump"):
        return True
    print("  Installing mitmproxy...", flush=True)
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "mitmproxy"],
        capture_output=True, text=True
    )
    return result.returncode == 0


def start():
    """Start mitmdump to capture HTTP/HTTPS traffic."""
    global _mitm_proc

    os.makedirs(MONITOR_DIR, exist_ok=True)
    log_path = os.path.join(MONITOR_DIR, "mitmproxy.log")
    flow_path = os.path.join(MONITOR_DIR, "traffic.flow")
    log_fd = open(log_path, "w")

    print("  Starting mitmdump on port 8080...", flush=True)
    _mitm_proc = subprocess.Popen(
        [
            "mitmdump", "--listen-port", "8080",
            "-w", flow_path,
            "--set", "block_global=false",
        ],
        stdout=log_fd,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(2)

    print(f"  Traffic log: {log_path}", flush=True)
    print(f"  Traffic dump: {flow_path}", flush=True)
    print("  Web UI: mitmweb --listen-port 8081", flush=True)
    return True


def install_cert():
    """Install mitmproxy CA certificate on the emulator for HTTPS decryption."""
    ca_cert = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.cer")
    if not os.path.isfile(ca_cert):
        print("  mitmproxy CA cert not found — run mitmproxy once to generate it")
        return False

    print("  Installing mitmproxy CA cert on emulator...", flush=True)
    _run([_adb(), "push", ca_cert, "/data/local/tmp/"])
    _run([_adb(), "shell",
          "openssl x509 -inform DER -in /data/local/tmp/mitmproxy-ca-cert.cer "
          "-out /data/local/tmp/mitmproxy-ca-cert.pem"])
    hash_result = _run([_adb(), "shell",
                        "openssl x509 -inform PEM -subject_hash_old "
                        "-in /data/local/tmp/mitmproxy-ca-cert.pem | head -1"])
    cert_hash = hash_result.stdout.strip()
    if not cert_hash:
        print("  Failed to get cert hash")
        return False

    _run([_adb(), "shell",
          f"cp /data/local/tmp/mitmproxy-ca-cert.pem /data/local/tmp/{cert_hash}.0"])
    _run([_adb(), "shell", "mount", "-o", "remount,rw", "/system"])
    _run([_adb(), "shell",
          f"cp /data/local/tmp/{cert_hash}.0 /system/etc/security/cacerts/"])
    _run([_adb(), "shell", "chmod", "644",
          f"/system/etc/security/cacerts/{cert_hash}.0"])
    print("  CA cert installed", flush=True)
    return True


def set_proxy():
    """Route emulator traffic through host mitmproxy."""
    print("  Setting emulator proxy to 10.0.2.2:8080...", flush=True)
    _run([_adb(), "shell", "settings", "put", "global", "http_proxy", "10.0.2.2:8080"])


def unset_proxy():
    """Remove proxy from emulator."""
    _run([_adb(), "shell", "settings", "delete", "global", "http_proxy"])
    print("  Proxy removed", flush=True)


def stop():
    """Stop mitmdump."""
    global _mitm_proc
    if _mitm_proc:
        _mitm_proc.terminate()
        _mitm_proc.wait(timeout=5)
    unset_proxy()
    print("  mitmdump stopped", flush=True)
