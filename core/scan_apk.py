import os
from androguard.core.apk import APK
from core.dex_scan import scan_dex

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


def scan_apk(apk_path: str) -> dict | None:
    if not os.path.exists(apk_path):
        print(f"File not found: {apk_path}")
        return None

    print(f"\nStarting static scan: {os.path.basename(apk_path)}")
    print("-" * 50)

    try:
        a = APK(apk_path)
    except Exception as e:
        print(f"Error parsing APK: {e}")
        return None

    app_name = a.get_app_name()
    package = a.get_package()
    target_sdk = a.get_target_sdk_version()

    print(f"App name   : {app_name}")
    print(f"Package    : {package}")
    print(f"Target SDK : {target_sdk}")

    all_perms = a.get_permissions()
    dangerous_found = [p for p in all_perms if p in DANGEROUS_PERMISSIONS]

    print(f"\nPermissions: {len(all_perms)} total, {len(dangerous_found)} dangerous")
    for p in dangerous_found:
        print(f"  \u26a0  {p}")

    print("\nRunning DEX analysis...")
    dex_results = scan_dex(apk_path)
    print(f"  Suspicious APIs : {len(dex_results['suspicious_apis'])}")
    print(f"  Embedded URLs   : {len(dex_results['urls'])}")
    print(f"  Embedded IPs    : {len(dex_results['ips'])}")
    print(f"  Native libs     : {len(dex_results['native_libs'])}")
    print(f"  Broadcast recv  : {len(dex_results['receivers'])}")

    return {
        "app_name": app_name,
        "package": package,
        "target_sdk": target_sdk,
        "all_permissions": all_perms,
        "dangerous_permissions": dangerous_found,
        **dex_results,
    }
