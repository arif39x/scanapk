import itertools
import os
import shutil
import subprocess
import sys
import time

FRIDA_VER = "17.12.0"
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
    kwargs.setdefault("timeout", 15)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    except subprocess.TimeoutExpired:
        print(f"  \u26a0 Command timed out: {' '.join(cmd[:4])}...")
        return None


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


def push_server(timeout: int = 120):
    """Push frida-server to emulator and start it."""
    local_path = download_server()
    size_mb = os.path.getsize(local_path) / (1024 * 1024)
    print(f"  Pushing frida-server ({size_mb:.0f} MB) to emulator...", flush=True)
    print(f"  (This can take 30-90s over emulator ADB)", flush=True)

    start = time.time()
    spinner = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

    proc = subprocess.Popen(
        [_adb(), "push", local_path, "/data/local/tmp/frida-server"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    while True:
        try:
            proc.wait(timeout=1)
            break
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start
            if elapsed > timeout:
                proc.kill()
                print(f"\n  \u2716 Timed out after {timeout}s — emulator ADB may be unresponsive")
                print("    Run 'adb devices' to check connectivity")
                return
            print(f"\r    {next(spinner)} {elapsed:.0f}s", end="", flush=True)

    elapsed = time.time() - start
    print(f"\r  \u2713 Done in {elapsed:.1f}s", flush=True)
    print("\r  Setting up frida-server...", end="", flush=True)

    _run([_adb(), "shell", "chmod", "755", "/data/local/tmp/frida-server"])
    _run([_adb(), "shell", "killall", "frida-server"])

    # Start frida-server in background via popen — adb shell with nohup & can block
    subprocess.Popen(
        [_adb(), "shell",
         "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(3)
    print("\r  \u2713 frida-server running on emulator", flush=True)


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
        ["frida", "-U", package_name, "-l", HOOKS_FILE],
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
