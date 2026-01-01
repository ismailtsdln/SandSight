# SandSight

**SandSight** is a cross-platform malware analysis and sandbox framework designed to provide safe static and dynamic analysis capabilities for security researchers and malware analysts.

![SandSight Banner](https://via.placeholder.com/800x200?text=SandSight+Framework)

## Features (Phase 1)

- **Static Analysis**:
  - **Windows PE**: Header info, sections, imports, exports, entropy.
  - **macOS Mach-O**: Architecture, commands, symbols.
  - **Android APK**: Permissions, activities, receivers, services.
  - **iOS IPA**: Plist info, permissions.
- **YARA Scanning**: Integrated YARA-X support for rule matching.
- **Reporting**: Generate JSON and HTML reports.
- **CLI**: Modern command-line interface with colored output.

## Installation

```bash
# Clone the repository
git clone https://github.com/ismailtsdln/SandSight.git
cd SandSight

# Install dependencies
pip install .
```

## Usage

### Scan a File

Perform a complete static analysis and generate a report.

```bash
sandsight scan malware_sample.exe
```

### Static Analysis Only

Run only static analysis and output JSON to console.

```bash
sandsight static malware_sample.apk --format json
```

### YARA Scan

Scan a file with default or custom YARA rules.

```bash
sandsight yara-scan malware_sample.bin
```

### Sandbox execution (Coming Soon)

```bash
sandsight sandbox-run malware_sample.exe
```

## Development

Run the CLI from source:

```bash
python3 -m sandsight.main --help
```

## License

MIT License
