<div align="center">

# 🛡️ JiaguSentinel Pro v2.0

### Advanced APK Unpacker & Malware Forensics Framework

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

*A modular, dual-engine framework for unpacking **360 Jiagu**-protected Android applications and performing deep malware forensics.*

</div>

---

## 🧬 Why 360 Jiagu?

**360 Jiagu (加固)** is one of China's most widely-deployed commercial Android packers, used by over 100,000 applications. While its legitimate purpose is to protect intellectual property, it is **heavily abused by malware authors** to evade static detection by antivirus engines.

**The problem:**
- Packed apps render traditional static analysis useless — the real DEX bytecode is encrypted inside native `.so` libraries
- The unpacking stub uses anti-debugging, anti-Frida, and integrity checks to prevent runtime extraction
- Security researchers need reliable tools to recover the original DEX for malware analysis

**JiaguSentinel's approach:**
- **Static Engine**: Entropy-based payload detection + byte-pattern matching + multi-layer decompression to extract DEX without execution
- **Dynamic Engine**: Frida-based memory dumping with advanced anti-detection bypass to capture decrypted DEX at runtime
- **Analytics Engine**: Automated threat scoring of extracted payloads for C2, exfiltration, and persistence indicators

---

## 🏗️ Architecture

```
JiaguSentinel/
├── main.py                 # Intelligent CLI/GUI router
├── core/
│   ├── static_engine.py    # Entropy analysis, LIEF, YARA, XOR brute-force
│   ├── dynamic_engine.py   # Frida injection, anti-anti-Frida, memory scanning
│   └── adb_manager.py      # Self-healing ADB, arch detection, Frida deployment
├── analytics/
│   ├── malware_scorer.py   # 40+ suspicious API patterns, threat scoring (0-100)
│   └── report_gen.py       # JSON + Markdown forensic reports
├── ui/
│   ├── gui_main.py         # CustomTkinter dark-mode tabbed UI
│   └── cli_main.py         # Rich + Click professional CLI
├── payloads/
│   └── dex_dump.js         # Enhanced Frida agent with ART hooks
├── rules/                  # Custom YARA rules (optional)
├── requirements.txt
└── README.md
```

---

## ⚡ Quick Start

### Prerequisites
- Python 3.10+
- Android device with **root access** (for dynamic engine)
- ADB installed and on PATH
- `frida-server` matching your device architecture

### Installation

```bash
git clone https://github.com/yourrepo/JiaguSentinel.git
cd JiaguSentinel
pip install -r requirements.txt
```

### Usage

#### GUI Mode (Default)
```bash
python main.py
```

#### CLI Mode
```bash
# Static analysis
python main.py --cli scan path/to/suspicious.apk

# Dynamic dump (requires rooted device + frida-server)
python main.py --cli dump com.suspicious.app

# Malware scoring on extracted DEX
python main.py --cli analyze unpacked_output/extracted.dex

# Generate forensic report
python main.py --cli report path/to/suspicious.apk -f both

# Device info
python main.py --cli device

# List available Frida payloads
python main.py --cli payloads

# JSON output for CI/CD
python main.py --cli --json-output scan suspicious.apk
```

---

## 🔬 Engine Deep Dive

### Static Engine
| Feature | Description |
|---------|-------------|
| **DEX Signature Scan** | Multi-version magic bytes (v035–v041) with header validation |
| **Entropy Heatmap** | Block-level Shannon entropy to pinpoint encrypted regions |
| **LIEF ELF Analysis** | Section entropy, symbol table, relocation scanning of `libjiagu*.so` |
| **Multi-Layer Decompress** | zlib → gzip → LZMA cascade on high-entropy blobs |
| **XOR Brute-Force** | Single-byte key recovery for XOR-encrypted payloads |
| **YARA Matching** | Custom rule scanning for packer and malware signatures |

### Dynamic Engine
| Feature | Description |
|---------|-------------|
| **Anti-Anti-Frida** | Hooks `open`, `read`, `strstr`, `access`, `fopen`, `connect` to hide Frida |
| **Memory DEX Scanner** | Scans all readable memory regions for DEX magic bytes |
| **ART Constructor Hook** | Intercepts `DexFile::OpenMemory` for early-stage capture |
| **InMemoryDexClassLoader** | Java-level hook for fileless DEX loading |
| **Periodic Rescan** | Catches late-decrypted DEX with configurable rescan intervals |
| **Session Recovery** | Auto-retry on transport errors with crash reports |

### Malware Scorer
| Category | Examples | Weight Range |
|----------|----------|-------------|
| **Exfiltration** | SmsManager, sendTextMessage, ContentResolver | 4.0–9.0 |
| **Surveillance** | Camera, AudioRecord, AccessibilityService, LocationManager | 4.0–9.0 |
| **Code Execution** | Runtime.exec, ProcessBuilder, DexClassLoader | 6.0–10.0 |
| **Persistence** | RECEIVE_BOOT_COMPLETED, DeviceAdminReceiver | 3.0–10.0 |
| **Network/C2** | Socket, WebSocket, DatagramSocket | 3.0–6.0 |
| **Evasion** | isDebuggerConnected, Build properties | 2.0–7.0 |

---

## 🧩 Extending JiaguSentinel

### Adding New Frida Payloads

1. Create a `.js` file in `payloads/`
2. Use `send({type: "dex_scan", results: [...]})` to report findings
3. The payload will automatically appear in the GUI dropdown and CLI

```javascript
// payloads/my_custom_hook.js
'use strict';
Java.perform(function() {
    // Your custom hooks here
    send({type: "dex_scan", results: [], total: 0});
});
```

### Adding Analytics Modules

Create a new module in `analytics/` following the `MalwareScorer` pattern:

```python
# analytics/my_analyzer.py
class MyAnalyzer:
    def analyze(self, dex_path: str) -> dict:
        # Your analysis logic
        return {"findings": [...]}
```

### Adding YARA Rules

Drop `.yar` files into a `rules/` directory — the static engine loads them automatically.

---

## 📄 Report Output

Reports are generated in both **JSON** (machine-readable) and **Markdown** (human-readable) formats:

- **JSON**: Full structured data for integration with SIEM/SOAR platforms
- **Markdown**: Formatted report with entropy heatmaps, threat score tables, and network indicators

---

## ⚠️ Legal Disclaimer

> **JiaguSentinel Pro is developed for authorized security research, malware analysis, and educational purposes ONLY.**
>
> Do NOT use this tool to bypass protections on applications you do not own or have explicit authorization to analyze. The authors assume no liability for misuse.
>
> Always comply with applicable laws, regulations, and terms of service.

---

## 📜 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions are welcome! Areas where help is needed:

- [ ] New YARA rules for emerging packer variants
- [ ] Custom Frida payloads for specific protection schemes
- [ ] Additional analytics modules (network traffic analysis, APK diff)
- [ ] Multi-language support for the GUI
- [ ] Unit tests and CI/CD pipeline

Please open an issue or PR on GitHub.

---

<div align="center">

**Built for the security research community.**

*If JiaguSentinel helped your research, consider starring the repo ⭐*

</div>
