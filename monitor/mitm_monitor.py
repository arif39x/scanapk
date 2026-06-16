import os
import shutil
import subprocess
import sys
import time

MONITOR_DIR = os.path.expanduser("~/scanapk_monitor")
_mitm_proc = None
_ADB_TIMEOUT = 15


def _adb():
    adb = shutil.which("adb")
    if not adb:
        adb = os.path.expanduser("~/Android/Sdk/platform-tools/adb")
    return adb


def _run(cmd, **kwargs):
    kwargs.setdefault("timeout", _ADB_TIMEOUT)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    except subprocess.TimeoutExpired:
        print(f"  \u26a0 Command timed out after {_ADB_TIMEOUT}s: {' '.join(cmd[:3])}...")
        return None


def install():
    """Install mitmproxy Python package."""
    if shutil.which("mitmdump"):
        return True
    print("  Installing mitmproxy...", flush=True)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "mitmproxy"],
            capture_output=True, text=True, timeout=120,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("  \u2716 mitmproxy install timed out")
        return False


def start():
    """Start mitmdump to capture HTTP/HTTPS traffic."""
    global _mitm_proc

    os.makedirs(MONITOR_DIR, exist_ok=True)
    log_path = os.path.join(MONITOR_DIR, "mitmproxy.log")
    flow_path = os.path.join(MONITOR_DIR, "traffic.flow")

    venv_mitmdump = os.path.join(os.path.dirname(sys.executable), "mitmdump")
    if not os.path.isfile(venv_mitmdump):
        venv_mitmdump = "mitmdump"

    print("  Starting mitmdump on port 8080...", flush=True)
    _mitm_proc = subprocess.Popen(
        [venv_mitmdump, "--listen-port", "8080", "-w", flow_path,
         "--set", "block_global=false"],
        stdout=open(log_path, "w"), stderr=subprocess.STDOUT, text=True,
    )
    time.sleep(2)
    print(f"  Traffic log: {log_path}", flush=True)
    return True


def _cert_hash_on_host(cert_path: str) -> str | None:
    """Compute Android-style cert hash using host openssl."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-inform", "PEM", "-subject_hash_old",
             "-in", cert_path],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip().split("\n")[0] if result.stdout.strip() else None
    except Exception:
        return None


def install_cert():
    """Install mitmproxy CA certificate on the emulator for HTTPS decryption."""
    ca_cert_cer = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.cer")
    ca_cert_pem = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

    # Prefer PEM (already exists from mitmproxy), fall back to DER→PEM conversion
    pem_source = ca_cert_pem if os.path.isfile(ca_cert_pem) else ca_cert_cer

    if not os.path.isfile(pem_source):
        print("  \u26a0 mitmproxy CA cert not found — run mitmproxy once to generate")
        print("    HTTPS decryption unavailable, but monitoring continues")
        return False

    print("  Installing mitmproxy CA cert on emulator...", flush=True)

    # If we only have DER, convert to PEM on host using Python
    if pem_source == ca_cert_cer:
        try:
            subprocess.run(
                ["openssl", "x509", "-inform", "DER",
                 "-in", ca_cert_cer, "-out", "/tmp/mitmproxy-ca-cert.pem"],
                capture_output=True, timeout=10,
            )
            pem_source = "/tmp/mitmproxy-ca-cert.pem"
        except Exception:
            print("  \u26a0 Host openssl missing — HTTPS decryption unavailable")
            print("    Install openssl: sudo apt install openssl")
            return False

    cert_hash = _cert_hash_on_host(pem_source)
    if not cert_hash:
        # Fallback: compute hash with Python's hashlib
        try:
            import hashlib
            with open(pem_source, "rb") as f:
                pem_data = f.read()
            # Extract subject from PEM and compute old-style MD5 hash
            import subprocess as sp
            # Try one more approach — openssl might work with different args
            result = sp.run(
                ["openssl", "x509", "-inform", "PEM", "-subject_hash_old",
                 "-in", pem_source],
                capture_output=True, text=True, timeout=10,
            )
            cert_hash = result.stdout.strip().split("\n")[0] if result.stdout.strip() else None
        except Exception:
            pass
        if not cert_hash:
            print("  \u26a0 Failed to compute cert hash — HTTPS decryption unavailable")
            return False

    _run([_adb(), "push", pem_source,
          f"/data/local/tmp/{cert_hash}.0"])
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
    _run([_adb(), "shell", "settings", "put", "global", "http_proxy",
          "10.0.2.2:8080"])


def unset_proxy():
    """Remove proxy from emulator."""
    _run([_adb(), "shell", "settings", "delete", "global", "http_proxy"])


def stop():
    """Stop mitmdump."""
    global _mitm_proc
    if _mitm_proc:
        _mitm_proc.terminate()
        _mitm_proc.wait(timeout=5)
    unset_proxy()
    print("  mitmdump stopped", flush=True)
