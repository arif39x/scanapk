import os

from androguard.core.apk import APK

DANGEROUS_PERMISSIONS = {
    # Manual Testing First Permisions
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    # Advanced UI & Overlay Risks (Highest Banking Risk)
    "android.permission.BIND_ACCESSIBILITY_SERVICE",  # Logs keys, scrapes screens, auto-clicks
    "android.permission.SYSTEM_ALERT_WINDOW",  # Draws fake login overlays over banking apps
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",  # Intercepts 2FA push notifications/tokens
    # Package & Environment Reconnaissance
    "android.permission.QUERY_ALL_PACKAGES",  # Detects which banking apps you have installed
    "android.permission.REQUEST_INSTALL_PACKAGES",  # Silently downloads/installs secondary payloads
    "android.permission.REQUEST_DELETE_PACKAGES",  # Uninstalls security apps or antivirus programs
    # Persistence & Device Control
    "android.permission.RECEIVE_BOOT_COMPLETED",  # Starts malware automatically when phone boots
    "android.permission.BIND_DEVICE_ADMIN",  # Prevents uninstallation, locks/wipes device
    # Modern Android Scoped Storage Risks (Android 13+)
    "android.permission.READ_MEDIA_IMAGES",  # Accesses photos (identity documents, QR codes)
    "android.permission.READ_MEDIA_VIDEO",  # Accesses local videos
    "android.permission.READ_MEDIA_AUDIO",  # Accesses audio recordings
    # Background Execution & Network
    "android.permission.INTERNET",  # Exfiltrates stolen credentials to attacker C2 servers
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",  # Keeps malware running persistently in the background
}


def scan_apk(apk_path):
    if not os.path.exists(apk_path):
        print(f"File not found at {apk_path}")
        return

    print(f"\nStarting scan for: {os.path.basename(apk_path)}")
    print("-" * 50)

    try:
        a = APK(apk_path)

        print(f"App Name:        {a.get_app_name()}")
        print(f"Package Name:    {a.get_package()}")
        print(f"Target SDK:      {a.get_target_sdk_version()}")
        print("-" * 50)

        permissions = a.get_permissions()
        print(f"Total Permissions Found: {len(permissions)}")

        dangerous_found = []
        for perm in permissions:
            if perm in DANGEROUS_PERMISSIONS:
                dangerous_found.append(perm)

        if dangerous_found:
            print("\n Unwanted / Dangerous Permissions Detected:")
            for perm in dangerous_found:
                print(f"  --> {perm}")
        else:
            print("\n No highly dangerous permissions flagged.")

    except Exception as e:
        print(f" Error processing APK: {e}")


if __name__ == "__main__":
    path_input = input("Enter the path to your APK file: ").strip()
    path_input = path_input.strip("'\"")

    scan_apk(path_input)
