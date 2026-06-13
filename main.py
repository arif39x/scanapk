from permissioncheck import scan_apk
from apkdeploy import deploy_to_emulator


if __name__ == "__main__":
    path_input = input("Enter the path to your APK file: ").strip()
    app_package = scan_apk(path_input)

    if app_package:
        choice = (
            input("\nDo you want to install and run this in the emulator now? (y/n): ")
            .strip()
            .lower()
        )
        if choice == "y":
            deploy_to_emulator(path_input, app_package)
