# Themida Dumper

Generic Themida/WinLicense payload extractor (v4.0). Launches a protected PE as a suspended process, detects section decryption at runtime, dumps the unpacked binary with fixed PE headers, and scans all process memory for IOCs.

## Features

- **Universal binary** -- x64 build handles both 32-bit (WOW64) and 64-bit targets
- **Section monitoring** -- Fingerprints encrypted sections, polls every 50ms (up to 300s) for decryption
- **Immediate suspend** -- Suspends target the moment decryption is detected (prevents ransomware damage)
- **Full PE dump** -- Memory dump with PE header fixup (`*_unpacked.exe`)
- **Individual section dumps** -- Each section saved as `{name}_0x{address}.bin`
- **IOC extraction** -- Scans all committed process memory for URLs, Bitcoin wallets, onion URLs, Telegram links, email addresses, ransom indicators, file extensions, registry keys, mutex names, WMI queries, system commands, file paths
- **Wide string scanning** -- Extracts both ASCII and UTF-16LE strings
- **Dropped file capture** -- Captures ransom notes and suspicious files (README, DECRYPT, .hta, .html, .txt) from the target directory
- **DLL support** -- Load DLLs via `--dll-export=<Name>` or `--dll-export=#1` (ordinal). Supports .dll, .ocx, .cpl
- **ServiceMain DLLs** -- Auto-creates a temporary Windows service for service DLLs
- **Anti-monitor bypass** -- Kills 50+ known analysis tools that Themida detects
- **VMware/VBox cleanup** -- Optional `--kill-vmtools` to kill virtualization guest tools and stop VM services
- **Password-protected output** -- Results packaged as `.dat` archive (ZipCrypto, password: `virus`)

## Supported Protectors

| Protector | Versions |
|-----------|----------|
| Themida | 1.x, 2.x, 3.x |
| WinLicense | 1.x, 2.x, 3.x |

## Architecture Support

| Build | Targets |
|-------|---------|
| x64 | 32-bit (WOW64) + 64-bit |
| x86 | 32-bit only |

## Usage

```bash
# EXE (drag & drop or command line)
themida_dumper_x64.exe <target.exe>

# EXE with VM tools cleanup
themida_dumper_x64.exe <target.exe> --kill-vmtools

# DLL (named export, required for DLLs)
themida_dumper_x64.exe sample.dll --dll-export=DllRegisterServer

# DLL (ordinal export)
themida_dumper_x64.exe sample.dll --dll-export=#1
```

> DLLs require `--dll-export` and cannot be drag-and-dropped.

## Output

Results are saved to `themida_dump_{filename}/` and packaged as a `.dat` archive:

```
themida_dump_malware.exe/
├── _text_0x401000.bin            # Individual section dumps
├── _rdata_0x410000.bin
├── malware.exe_unpacked.exe      # Full PE dump with fixed headers
├── extracted_strings.txt         # IOC strings (ASCII + wide)
├── README.txt                    # Captured ransom notes (if any)
└── DECRYPT_FILES.hta
```

## Building

Requires [MinGW-w64](https://www.mingw-w64.org/).

```bash
# 64-bit build (recommended)
x86_64-w64-mingw32-gcc -O2 -s -static -o themida_dumper_x64.exe themida_dumper_universal.c

# 32-bit build
i686-w64-mingw32-gcc -O2 -s -static -o themida_dumper_x86.exe themida_dumper_universal.c
```

## How It Works

1. Enables SeDebugPrivilege and kills known analysis tools
2. Launches target PE as a SUSPENDED process
3. Detects target architecture (WOW64 or native x64)
4. Fingerprints each PE section (64 bytes)
5. Resumes the process and polls sections every 50ms
6. When fingerprints change (decryption detected), immediately suspends
7. Dumps all sections and full PE with header fixup
8. Scans all committed memory regions for IOC strings
9. Captures dropped ransom notes from target directory
10. Packages everything into a password-protected `.dat` file
11. Terminates target and cleans up temp services

## Notes

- Run in an isolated VM -- this tool executes malware samples
- The x64 build is recommended as it handles both architectures
- The tool kills common analysis tools before launching the target to avoid Themida's anti-analysis detection
- Output `.dat` files are ZIP archives renamed to `.dat` (password: `virus`)

## License

MIT
