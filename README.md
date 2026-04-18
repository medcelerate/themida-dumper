# Themida Dumper (Multi-Mode)

Generic PE payload extractor with Memory Harvester (v6.1). One source, three modes: **themida**, **vmprotect**, **runtime**. Launches a sample as a suspended process, detects section decryption or executes freely for generic memory capture, dumps the unpacked binary with fixed PE headers, and scans all process memory for IOCs.

## Modes

| Mode | Binary | When to use |
|------|--------|-------------|
| `themida` | `themida_dumper_{x64,x86}.exe` | Themida/WinLicense-packed samples (packer check gates execution) |
| `vmprotect` | `vmprotect_dumper_{x64,x86}.exe` | VMProtect-packed samples (packer check gates execution) |
| `runtime` | `runtime_dumper_{x64,x86}.exe` | Generic memory capture for any sample (no packer required) |

Mode is baked into the binary via `-DDEFAULT_MODE=MODE_*` at build time, or overridden at runtime with `--mode=<name>`.

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
- **Memory Harvester** -- Dynamic executable region tracking with rolling 500ms snapshots, fingerprint-based change detection, captures ephemeral unpacked code outside PE image
- **PE-sieve integration** -- Auto-detects pe-sieve at C:\Tools\, runs for advanced unpacking validation
- **Behavioral triggers** -- Monitors Desktop, TEMP, APPDATA for new file drops; triggers dump on ransomware activity
- **Harvest report** -- harvest_report.txt with full region timeline, section status, PE-sieve results
- **Smart dropper mode** -- Filesystem + process monitoring discovers packed payloads dropped by the sample
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

Requires [MinGW-w64](https://www.mingw-w64.org/). The same source compiles into three binary variants by setting `-DDEFAULT_MODE`:

```bash
# Themida mode (original behavior, packer check gates execution)
x86_64-w64-mingw32-gcc -O2 -s -static -DDEFAULT_MODE=MODE_THEMIDA   -o themida_dumper_x64.exe   themida_dumper_universal.c
i686-w64-mingw32-gcc   -O2 -s -static -DDEFAULT_MODE=MODE_THEMIDA   -o themida_dumper_x86.exe   themida_dumper_universal.c

# VMProtect mode
x86_64-w64-mingw32-gcc -O2 -s -static -DDEFAULT_MODE=MODE_VMPROTECT -o vmprotect_dumper_x64.exe themida_dumper_universal.c
i686-w64-mingw32-gcc   -O2 -s -static -DDEFAULT_MODE=MODE_VMPROTECT -o vmprotect_dumper_x86.exe themida_dumper_universal.c

# Runtime mode (generic, no packer check)
x86_64-w64-mingw32-gcc -O2 -s -static -DDEFAULT_MODE=MODE_RUNTIME   -o runtime_dumper_x64.exe   themida_dumper_universal.c
i686-w64-mingw32-gcc   -O2 -s -static -DDEFAULT_MODE=MODE_RUNTIME   -o runtime_dumper_x86.exe   themida_dumper_universal.c
```

If `-DDEFAULT_MODE` is omitted, the binary defaults to `MODE_THEMIDA`. Pass `--mode=themida|vmprotect|runtime` at runtime to override the compiled default.

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

## What's New in v6.1

- **Multi-mode** — `--mode=themida|vmprotect|runtime` flag; same source compiles into three binaries via `-DDEFAULT_MODE`.
- **Runtime mode** — generic memory harvester for any sample. Skips packer detection entirely, launches the target in direct mode, and lets the Memory Harvester capture executable regions on a rolling 500 ms interval. Intended for samples where static analysis hits encrypted strings, API hashing, or crypto routines that only resolve at runtime — dump output can be fed back to IDA/Ghidra for a second pass.
- **Output naming** — `themida_dump_*` / `vmp_dump_*` / `runtime_dump_*` prefix selected by mode.
- **Harvest report title** — includes the mode name: `=== Clarity {Themida|VMProtect|Runtime} Memory Harvester v6.1 Report ===`.

## What's New in v6.0

| Feature | v4.0 | v6.0 |
|---------|------|------|
| Region tracking | None | Rolling snapshots every 500ms |
| PE-sieve | None | Auto-detect + run on target PID |
| Behavioral trigger | None | File drop monitoring in watched dirs |
| Harvest report | None | Full timeline + region summary |
| Dropper mode | Basic | Smart filesystem + process scanning |
| Region dumps | None | `region_*.bin` for all exec regions |
| CLI options | 6 | 10 (`--no-harvest`, `--pesieve-path`, etc.) |
