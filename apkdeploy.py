import os
import shutil
import subprocess
import sys
import time


EMULATOR_NAME = "scanapk_test"
SYSTEM_IMAGE = "system-images;android-30;google_apis;x86_64"


def _run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def _sdk_path():
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        path = os.environ.get(var)
        if path and os.path.isdir(path):
            return path
    candidates = [
        os.path.expanduser("~/Android/Sdk"),
        os.path.expanduser("~/.android/sdk"),
        "/opt/android-sdk",
        "/usr/lib/android-sdk",
    ]
    for c in candidates:
        if os.path.isdir(c):
            return c
    return os.path.expanduser("~/Android/Sdk")


def _emulator_path():
    sdk = _sdk_path()
    candidates = [
        shutil.which("emulator"),
        os.path.join(sdk, "emulator", "emulator"),
        os.path.join(sdk, "emulator", "qemu", "linux-x86_64", "qemu-system-x86_64-headless"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def _avdmanager_path():
    sdk = _sdk_path()
    candidates = [
        shutil.which("avdmanager"),
        os.path.join(sdk, "cmdline-tools", "latest", "bin", "avdmanager"),
        os.path.join(sdk, "tools", "bin", "avdmanager"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def _sdkmanager_path():
    sdk = _sdk_path()
    candidates = [
        shutil.which("sdkmanager"),
        os.path.join(sdk, "cmdline-tools", "latest", "bin", "sdkmanager"),
        os.path.join(sdk, "tools", "bin", "sdkmanager"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def _env():
    env = os.environ.copy()
    env["ANDROID_HOME"] = _sdk_path()
    return env


def _adb():
    adb = shutil.which("adb")
    if not adb:
        adb = os.path.join(_sdk_path(), "platform-tools", "adb")
    return adb


def emulator_running():
    result = _run([_adb(), "devices"])
    for line in result.stdout.splitlines():
        if "emulator" in line and "device" in line:
            return True
    return False


def wait_for_boot(timeout=180):
    print("  Waiting for emulator to boot...", end="", flush=True)
    start = time.time()
    while time.time() - start < timeout:
        result = _run([_adb(), "shell", "getprop", "sys.boot_completed"])
        if result.stdout.strip() == "1":
            print(f" done ({int(time.time() - start)}s)")
            return True
        time.sleep(5)
        print(".", end="", flush=True)
    print(" timeout!")
    return False


def install_sdk():
    sdk = _sdk_path()
    print("Android SDK not found. Setting up automatically...")

    url = "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
    zip_path = os.path.join(sdk, "cmdline-tools.zip")
    os.makedirs(sdk, exist_ok=True)

    print("  Downloading command-line tools...", flush=True)
    import urllib.request
    urllib.request.urlretrieve(url, zip_path)

    print("  Extracting...", flush=True)
    import zipfile
    import shutil
    extract_dir = os.path.join(sdk, "cmdline-tools")
    if os.path.isdir(extract_dir):
        shutil.rmtree(extract_dir)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_dir)
    src = os.path.join(extract_dir, "cmdline-tools")
    dst = os.path.join(extract_dir, "latest")
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    shutil.move(src, dst)
    os.remove(zip_path)

    sdkmanager = _sdkmanager_path()
    os.chmod(sdkmanager, 0o755)

    print("  Accepting licenses...", flush=True)
    subprocess.run(f"yes 2>/dev/null | '{sdkmanager}' --licenses", shell=True,
                   env=_env(), capture_output=True)

    print("  Installing platform-tools and emulator...", flush=True)
    subprocess.run([sdkmanager, "platform-tools", "emulator"],
                   env=_env(), capture_output=True)

    avdmanager = _avdmanager_path()
    if avdmanager:
        os.chmod(avdmanager, 0o755)

    print(f"  SDK ready at {sdk}", flush=True)
    return True


def ensure_sdk():
    if _emulator_path() and _avdmanager_path():
        return True
    return install_sdk()


def ensure_avd():
    avdmanager = _avdmanager_path()
    result = _run([avdmanager, "list", "avd", "-c"], env=_env())
    if EMULATOR_NAME in result.stdout:
        return True

    sdkmanager = _sdkmanager_path()
    print(f"  Installing system image {SYSTEM_IMAGE}...", flush=True)
    subprocess.run([sdkmanager, SYSTEM_IMAGE], env=_env(), capture_output=True)

    print(f"  Creating AVD '{EMULATOR_NAME}'...", flush=True)
    result = _run(
        [avdmanager, "create", "avd", "-n", EMULATOR_NAME, "-k", SYSTEM_IMAGE, "-d", "pixel_6"],
        env=_env(),
        input="no",
    )
    return result.returncode == 0


def start_emulator():
    print("\n" + "=" * 50)
    print(" Starting Android Emulator")
    print("=" * 50)

    if emulator_running():
        print("-> Killing existing emulator...")
        _run([_adb(), "emu", "kill"])
        time.sleep(5)

    ensure_sdk()
    ensure_avd()

    emulator = _emulator_path()
    print(f"  Launching emulator: {emulator}", flush=True)
    subprocess.Popen(
        [emulator, "-avd", EMULATOR_NAME, "-no-audio", "-gpu", "swiftshader_indirect",
         "-no-snapshot", "-memory", "2048"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=_env(),
    )

    time.sleep(10)

    if not wait_for_boot():
        print("-> Failed to boot emulator")
        return False

    print("-> Emulator is ready")
    return True


def deploy_to_emulator(apk_path, package_name):
    if not start_emulator():
        return False

    print(f"  Installing {os.path.basename(apk_path)}...")
    install_proc = _run([_adb(), "install", "-r", apk_path])

    if "Success" in install_proc.stdout:
        print("-> Installation successful!")
    else:
        print(f"-> Installation failed.\nADB: {install_proc.stdout}{install_proc.stderr}")
        return False

    print(f"  Launching {package_name}...")
    launch_proc = _run([
        _adb(), "shell", "monkey",
        "-p", package_name,
        "-c", "android.intent.category.LAUNCHER", "1",
    ])

    if launch_proc.returncode == 0:
        print("-> App successfully launched on the emulator!")
        return True
    else:
        print(f"-> Failed to launch.\nADB: {launch_proc.stderr}")
        return False
