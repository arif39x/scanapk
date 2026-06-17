# <img src="asset/scanapkmascot.png" width="100" align="center"> ScanAPK

**ScanAPK** is an advanced, AI-powered Android malware analysis tool that combines static scanning, dynamic monitoring, and agentic AI reasoning to provide comprehensive security assessments of APK files.

---

## Overview

ScanAPK doesn't just look at code; it observes behavior and reasons like a human analyst. By integrating traditional security tools with Large Language Models (LLMs), it can identify complex threat patterns, data exfiltration attempts, and sophisticated malware families.

### Core Capabilities

*   **Static Analysis**: Deep scans of DEX files, manifest components, and resources to extract suspicious APIs, hardcoded URLs/IPs, and dangerous permissions.
*   **Dynamic Monitoring**: Automatically deploys the APK to an emulator and monitors it in real-time using:
    *   **Frida Hooks**: Deep instrumentation of Crypto, SMS, File System, and Privacy-sensitive APIs.
    *   **MITMproxy**: Interception and analysis of network traffic (HTTP/HTTPS).
    *   **Logcat**: Real-time filtering for suspicious system-level events.
*   **Agentic AI Reasoning**: An LLM-based agent (via OpenRouter) processes all collected evidence into a unified **Knowledge Graph**. The agent can then:
    *   Reason about the combined threat of multiple indicators.
    *   Autonomously use tools to perform deeper investigations (e.g., searching for specific strings or analyzing native libs).
    *   Provide a structured risk score, severity level, and actionable recommendations.

---

## 🛠️ Tools Used

ScanAPK leverages the following industry-standard tools:
- **Androguard**: For robust static analysis of APK files.
- **Frida**: For dynamic instrumentation and API hooking.
- **MITMproxy**: For intercepting and logging network traffic.
- **OpenRouter (OpenAI SDK)**: For powering the agentic reasoning engine.
- **Adb/Emulator**: For automated deployment and interaction.

---

##  Installation & Setup

### Prerequisites
- Python 3.12+
- Android Emulator (with ADB enabled)
- Frida-server (automatically pushed if not present)
- OpenRouter API Key

### Setup
1.  **Clone the repository**:
    ```bash
    git clone https://github.com/arif39x/scanapk
    cd scanapk
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure Environment**:
    Create a `.env` file in the root directory and add your OpenRouter API key:
    ```env
    OPENROUTER_API_KEY=your_api_key_here
    ```

---

##  How to Use

Simply run the `main.py` script with the path to your APK:

```bash
python main.py path/to/app.apk
```

### Command Line Options
- `--static`: Run static analysis only (skips emulator and dynamic monitoring).
- `--observe <seconds>`: Duration for dynamic monitoring (default: 60s).
- `--no-ai`: Skip the AI reasoning phase and produce a report based only on raw evidence.

### Workflow
1.  **Static Scan**: The tool performs an immediate analysis of the APK's structure.
2.  **Deployment**: You will be prompted to install the app on a running emulator.
3.  **Observation**: The app is launched, and you should interact with it while Frida, MITMproxy, and Logcat capture its behavior.
4.  **AI Analysis**: The agent processes the logs and evidence to determine the risk level.
5.  **Report**: A detailed report is generated and saved locally.

---

##  Sample Output (AI Assessment)
```json
{
  "risk_score": 85,
  "severity": "CRITICAL",
  "malware_family": "Spyware/SmsStealer",
  "threat_types": ["Data Exfiltration", "SMS Monitoring"],
  "key_findings": [
    "App requests BIND_ACCESSIBILITY_SERVICE without clear utility.",
    "Dynamic hooks detected calls to SMS send APIs during startup.",
    "Network logs show encrypted payloads being sent to a known malicious IP."
  ]
}
```

### By Dev For Dev
