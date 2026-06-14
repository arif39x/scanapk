import argparse
import os
import sys

from dotenv import load_dotenv
load_dotenv()


def main():
    parser = argparse.ArgumentParser(description="APK Malware Analyser")
    parser.add_argument("apk", nargs="?", help="Path to APK file")
    parser.add_argument(
        "--static", action="store_true",
        help="Static analysis only — skip emulator and dynamic monitoring"
    )
    parser.add_argument(
        "--observe", type=int, default=60,
        help="Seconds to monitor the running app (default: 60)"
    )
    parser.add_argument(
        "--no-ai", action="store_true",
        help="Skip AI analysis (produces evidence-only report)"
    )
    args = parser.parse_args()

    apk_path = args.apk
    if not apk_path:
        apk_path = input("Enter path to APK file: ").strip()

    apk_path = os.path.expanduser(apk_path)
    if not os.path.isfile(apk_path):
        print(f"File not found: {apk_path}")
        sys.exit(1)

    from core.scan_apk import scan_apk
    from core.apkdeploy import deploy_to_emulator

    static_info = scan_apk(apk_path)
    if static_info is None:
        sys.exit(1)

    evidence = {}
    if not args.static:
        choice = input(
            "\nInstall and run in emulator for dynamic analysis? (y/n): "
        ).strip().lower()

        if choice == "y":
            if deploy_to_emulator(apk_path, static_info["package"]):
                from monitor import start_all
                evidence = start_all(
                    static_info["package"],
                    observe_secs=args.observe,
                )
            else:
                print("Emulator deployment failed — continuing with static results only.")
    else:
        print("\n[Static-only mode] Skipping emulator.")

    ai_result = {}
    if not args.no_ai:
        if not os.environ.get("OPENROUTER_API_KEY"):
            print("\nOPENROUTER_API_KEY not set.")
            skip = input("Skip AI analysis? (y/n): ").strip().lower()
            if skip != "y":
                key = input("Paste your OpenRouter API key: ").strip()
                os.environ["OPENROUTER_API_KEY"] = key

        if os.environ.get("OPENROUTER_API_KEY"):
            print("\nRunning agentic analysis with Nemotron 3 Ultra...")
            from core.agent import analyse
            ai_result = analyse(
                apk_path=apk_path,
                static_info=static_info,
                evidence=evidence,
            )
        else:
            print("Skipping AI analysis.")

    from report.generator import generate
    report_path = generate(static_info, ai_result)
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
