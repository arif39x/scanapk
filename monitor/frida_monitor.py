import os
import shutil
import subprocess
import sys
import time

FRIDA_VER = "16.5.9"
FRIDA_URL = (
    f"https://github.com/frida/frida/releases/download/{FRIDA_VER}/"
    f"frida-server-{FRIDA_VER}-android-x86_64.xz"
)
FRIDA_BIN = f"frida-server-{FRIDA_VER}-android-x86_64"
MONITOR_DIR = os.path.expanduser("~/scanapk_monitor")
HOOKS_FILE = os.path.join(os.path.dirname(__file__), "hooks.js")
_frida_proc = None


def _adb():
    adb = shutil.which("adb")
    if not adb:
        adb = os.path.expanduser("~/Android/Sdk/platform-tools/adb")
    return adb


def _run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def install():
    """Install frida-tools Python package."""
    if shutil.which("frida"):
        return True
    print("  Installing frida-tools...", flush=True)
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "frida-tools"],
        capture_output=True, text=True
    )
    return result.returncode == 0


def download_server():
    """Download frida-server binary for Android x86_64."""
    os.makedirs(MONITOR_DIR, exist_ok=True)
    local_path = os.path.join(MONITOR_DIR, FRIDA_BIN)
    if os.path.isfile(local_path):
        return local_path

    print("  Downloading frida-server...", flush=True)
    import urllib.request
    import lzma
    xz_path = local_path + ".xz"
    urllib.request.urlretrieve(FRIDA_URL, xz_path)
    with lzma.open(xz_path) as f_in, open(local_path, "wb") as f_out:
        f_out.write(f_in.read())
    os.remove(xz_path)
    os.chmod(local_path, 0o755)
    return local_path


def push_server():
    """Push frida-server to emulator and start it."""
    local_path = download_server()
    print("  Pushing frida-server to emulator...", flush=True)
    _run([_adb(), "push", local_path, "/data/local/tmp/frida-server"])
    _run([_adb(), "shell", "chmod", "755", "/data/local/tmp/frida-server"])

    _run([_adb(), "shell", "killall", "frida-server"])
    time.sleep(1)
    _run([_adb(), "shell", "nohup", "/data/local/tmp/frida-server", "&"])
    time.sleep(3)
    print("  frida-server running on emulator", flush=True)


def attach(package_name):
    """Attach Frida hooks to a running app."""
    global _frida_proc

    if not os.path.isfile(HOOKS_FILE):
        print(f"  hooks.js not found at {HOOKS_FILE}")
        return False

    log_path = os.path.join(MONITOR_DIR, "frida_hooks.log")
    log_fd = open(log_path, "w")

    print(f"  Attaching Frida hooks to {package_name}...", flush=True)
    _frida_proc = subprocess.Popen(
        ["frida", "-U", package_name, "-l", HOOKS_FILE, "--no-pause"],
        stdout=log_fd,
        stderr=subprocess.STDOUT,
        text=True,
    )
    print(f"  Frida log: {log_path}", flush=True)
    return True


def stop():
    """Stop frida-server on emulator."""
    global _frida_proc
    if _frida_proc:
        _frida_proc.terminate()
        _frida_proc.wait(timeout=5)
    _run([_adb(), "shell", "killall", "frida-server"])
    print("  Frida stopped", flush=True)
