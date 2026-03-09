# Themida Dumper

Generic Themida/WinLicense payload extractor. Launches a protected PE as a suspended process, detects section decryption at runtime, dumps the unpacked binary with fixed PE headers, and scans all process memory for IOCs.

## Features

- **Universal binary** -- x64 build handles both 32-bit (WOW64) and 64-bit targets
- **Section monitoring** -- Fingerprints encrypted sections, polls every 50ms (up to 300s) for decryption
- **Immediate suspend** -- Suspends target the moment decryption is detected (prevents ransomware damage)
- **Full PE dump** -- Memory dump with PE header fixup (`*_unpacked.exe`)
- **Individual section dumps** -- Each section saved as `{name}_0x{address}.bin`
- **IOC extraction** -- Scans all committed process memory for:
  - URLs (http/https/ftp)
  - Bitcoin wallet addresses
  - Onion URLs
  - Email addresses
  - Ransom note indicators
  - Targeted file extensions
  - Registry keys
  - Mutex names
  - WMI queries
  - System commands (cmd, powershell, wmic, etc.)
- **Ransom note capture** -- Detects and saves dropped ransom notes from target directory
- **DLL support** -- Load DLLs via `--dll-export=<Name>` or `--dll-export=#1` (ordinal)
- **ServiceMain DLLs** -- Auto-creates a temporary Windows service for service DLLs
- **Anti-monitor bypass** -- Kills known analysis tools that Themida detects (Process Monitor, Wireshark, IDA, x64dbg, OllyDbg, API Monitor, etc.)
- **VMware/VBox cleanup** -- Optional `--kill-vmtools` to kill virtualization guest tools
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
# EXE target
themida_dumper_x64.exe <target.exe> [output_dir] [--kill-vmtools]

# DLL target (named export)
themida_dumper_x64.exe sample.dll --dll-export=DllRegisterServer

# DLL target (ordinal export)
themida_dumper_x64.exe sample.dll --dll-export=#1

# Drag & drop
# Simply drag a protected PE onto the executable
```

## Output

Results are saved to a folder and packaged as a `.dat` archive:

```
themida_dump_{filename}/
├── .text_0x00401000.bin          # Individual section dumps
├── .rdata_0x00410000.bin
├── {filename}_unpacked.exe       # Full PE dump with fixed headers
├── heap_strings.txt              # Extracted IOC strings
└── ransom_notes/                 # Captured ransom notes (if any)
```

## Building

Requires [MinGW-w64](https://www.mingw-w64.org/).

```bash
# 64-bit build (recommended -- handles both 32-bit and 64-bit targets)
x86_64-w64-mingw32-gcc -O2 -s -static -o themida_dumper_x64.exe themida_dumper_universal.c

# 32-bit build (for 32-bit-only VMs)
i686-w64-mingw32-gcc -O2 -s -static -o themida_dumper_x86.exe themida_dumper_universal.c
```

## How It Works

1. **Launch** -- Target PE is created as a SUSPENDED process
2. **Detect architecture** -- Queries WOW64 status to determine 32-bit vs 64-bit
3. **Fingerprint** -- Reads 64 bytes from each PE section to create a baseline
4. **Monitor** -- Resumes the process and polls sections every 50ms
5. **Detect decryption** -- When section fingerprints change, decryption has occurred
6. **Suspend & dump** -- Immediately suspends the process, dumps all sections and full PE
7. **Scan memory** -- Walks all committed memory regions for IOC strings
8. **Capture artifacts** -- Saves ransom notes and dropped files
9. **Archive** -- Packages everything into a password-protected `.dat` file
10. **Terminate** -- Kills the target process

## Notes

- Run in an isolated VM -- this tool executes malware samples
- The x64 build is recommended as it handles both architectures
- The tool kills common analysis tools before launching the target to avoid Themida's anti-analysis detection
- Output `.dat` files are ZIP archives renamed to `.dat` (password: `virus`)

## License

MIT
