from core import scan_apk, deploy_to_emulator


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

            monitor_choice = (
                input("\nStart API behavior monitoring (Frida + mitmproxy + logcat)? (y/n): ")
                .strip()
                .lower()
            )
            if monitor_choice == "y":
                from monitor import start_all
                start_all(app_package)
