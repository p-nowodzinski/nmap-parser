# Nmap Parser

A Python-based tool to parse Nmap XML scan results and generate structured outputs in CSV, JSON, and HTML formats.  

## Features

- **Run Nmap scans or parse existing XML**: Supports both fresh scans and parsing pre-existing scan outputs.  
- **Multiple output formats**: CSV, JSON, HTML, or all formats at once.  
- **Processing Instruction (PI) handling**: Detects and updates XML XSL processing instructions to ensure HTML generation works, even on systems without Nmap installed.  
- **Bundled XSL stylesheet**: Ensures Linux users can transform XML to HTML without relying on external URLs.  
- **Verbose logging**: Control output detail with `-v` or `-vv` flags.  
- **Scan presets**: Quick, full, service, script, aggressive, and UDP scans supported.  
- **Portable output**: Output files stored in a dedicated `output/` directory.

## Installation

```bash
git clone https://github.com/p-nowodzinski/nmap-parser.git
cd nmap-parser
```

## Usage

Run new Nmap scan:
```bash
python3 scripts/main.py run 192.168.0.1/24 --format all --auto-open both -vv --overwrite --scan-preset default
```
Parse an existing XML scan:
```bash
python3 scripts/main.py parse output/nmap_out.xml --format html --overwrite
```

## Notes

- The output/ directory is used for all scan outputs.
- On Linux, the bundled XSL stylesheet is used for HTML generation to avoid external dependencies.
- If an XML file is missing a processing instruction or points to a missing XSL, the script will prompt the user with options to fix it.