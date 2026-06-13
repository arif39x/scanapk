import os

from androguard.core.apk import APK

DANGEROUS_PERMISSIONS = {
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
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.INTERNET",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
}


def scan_apk(apk_path):
    if not os.path.exists(apk_path):
        print(f"File not found at {apk_path}")
        return None

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

        return a.get_package()

    except Exception as e:
        print(f" Error processing APK: {e}")
        return None
