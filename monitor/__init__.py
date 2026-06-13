import atexit

from . import frida_monitor, logcat_monitor, mitm_monitor


def start_all(package_name):
    print("\n" + "=" * 50)
    print(" Setting up API behavior monitoring")
    print("=" * 50)

    ok = True
    ok &= frida_monitor.install()
    ok &= mitm_monitor.install()
    if not ok:
        print("  Failed to install dependencies")
        return False

    frida_monitor.push_server()
    mitm_monitor.start()
    mitm_monitor.install_cert()
    mitm_monitor.set_proxy()
    frida_monitor.attach(package_name)
    logcat_monitor.start()

    atexit.register(stop_all)

    print("\n" + "-" * 50)
    print(" Monitoring active!")
    print(f"  Frida hooks:   ~/scanapk_monitor/frida_hooks.log")
    print(f"  mitmproxy:     ~/scanapk_monitor/mitmproxy.log")
    print(f"  Traffic dump:  ~/scanapk_monitor/traffic.flow")
    print(f"  Logcat:        ~/scanapk_monitor/logcat_monitor.log")
    print("-" * 50)
    print("  mitmproxy web UI: mitmweb --listen-port 8081")
    print("  Press Ctrl+C to stop monitoring")
    print("-" * 50 + "\n")
    return True


def stop_all():
    frida_monitor.stop()
    mitm_monitor.stop()
    logcat_monitor.stop()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m monitor <package_name>")
        sys.exit(1)
    start_all(sys.argv[1])
