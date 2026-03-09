/* themida_dumper_universal.c - Themida/WinLicense dumper (x86+x64)
 * gcc: x86_64-w64-mingw32-gcc -O2 -s -static -o themida_dumper_x64.exe themida_dumper_universal.c
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN64
#define ADDR_FMT    "0x%llX"
#define ADDR_FMTW   "0x%016llX"
#define ADDR_CAST(x) (unsigned long long)(x)
#else
#define ADDR_FMT    "0x%08X"
#define ADDR_FMTW   "0x%08X"
#define ADDR_CAST(x) (unsigned)(x)
#endif

#define MAX_SECTIONS        32
#define POLL_INTERVAL_MS    50
#define MAX_MONITOR_SEC     300
#define FINGERPRINT_SIZE    64
#define MAX_STRINGS         4096
#define MIN_STR_LEN         4
#define MAX_STR_LEN         1024

#define PE32_MAGIC          0x10b
#define PE32PLUS_MAGIC      0x20b

#define ProcessBasicInformation     0
#define ProcessWow64Information     26

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _MY_PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} MY_PROCESS_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength
);

typedef struct {
    char      name[16];
    DWORD     rva;
    DWORD     vsize;
    DWORD     raw_size;
    BYTE      fingerprint[FINGERPRINT_SIZE];
    int       changed;
} SectionInfo;

static SectionInfo  g_sections[MAX_SECTIONS];
static int          g_num_sections = 0;
static ULONG_PTR    g_image_base = 0;
static int          g_is_32bit_target = 0;
static WORD         g_pe_magic = 0;
static char         g_output_dir[MAX_PATH] = ".";
static char         g_dll_export[256] = "";
static int          g_is_dll = 0;
static int          g_is_service_dll = 0;

static pfnNtQueryInformationProcess g_NtQueryInformationProcess = NULL;

static int is_btc_address(const char *s)
{
    int len = (int)strlen(s);
    if (len < 26 || len > 62) return 0;
    if (s[0] == '1' || s[0] == '3' || (s[0] == 'b' && s[1] == 'c' && s[2] == '1'))
        return 1;
    return 0;
}

static int is_onion_url(const char *s)
{
    return strstr(s, ".onion") != NULL;
}

static int is_url(const char *s)
{
    return strstr(s, "http:
           strstr(s, "t.me/") != NULL || strstr(s, "ftp:
}

static int is_email(const char *s)
{
    const char *at = strchr(s, '@');
    if (!at) return 0;
    return strchr(at, '.') != NULL;
}

static int is_extension(const char *s)
{
    if (s[0] != '.') return 0;
    int len = (int)strlen(s);
    if (len < 3 || len > 12) return 0;
    for (int i = 1; i < len; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
            return 0;
    }
    return 1;
}

static int is_ransom_indicator(const char *s)
{
    return strstr(s, "README") != NULL || strstr(s, "readme") != NULL ||
           strstr(s, "DECRYPT") != NULL || strstr(s, "decrypt") != NULL ||
           strstr(s, "RESTORE") != NULL || strstr(s, "restore") != NULL ||
           strstr(s, "RECOVER") != NULL || strstr(s, "recover") != NULL ||
           strstr(s, "RANSOM") != NULL || strstr(s, "ransom") != NULL ||
           strstr(s, "Your files") != NULL || strstr(s, "your files") != NULL ||
           strstr(s, "YOUR FILES") != NULL || strstr(s, "encrypted") != NULL ||
           strstr(s, "Bitcoin") != NULL || strstr(s, "bitcoin") != NULL ||
           strstr(s, "Telegram") != NULL || strstr(s, "telegram") != NULL ||
           strstr(s, "payment") != NULL || strstr(s, "wallet") != NULL;
}

static const char* categorize_string(const char *s)
{
    if (is_btc_address(s)) return "btc_wallet";
    if (is_onion_url(s)) return "onion_url";
    if (is_url(s)) return "url";
    if (is_email(s)) return "email";
    if (is_ransom_indicator(s)) return "ransom";
    if (is_extension(s)) return "extension";
    if (strstr(s, ":\\") || strstr(s, "C:\\") || strstr(s, "\\Windows")) return "path";
    if (strstr(s, ".exe") || strstr(s, ".dll") || strstr(s, ".sys")) return "file";
    if (strstr(s, "mutex") || strstr(s, "Mutex") || strstr(s, "Global\\")) return "mutex";
    if (strstr(s, "SELECT") || strstr(s, "FROM") || strstr(s, "Win32_")) return "wmi";
    if (strstr(s, "bcdedit") || strstr(s, "wbadmin") || strstr(s, "vssadmin") ||
        strstr(s, "wevtutil") || strstr(s, "powershell")) return "command";
    if (strstr(s, "HKEY_") || strstr(s, "SOFTWARE\\") || strstr(s, "CurrentVersion")) return "registry";
    return NULL;
}

static int detect_target_architecture(HANDLE hProcess, ULONG_PTR *out_image_base)
{
    SIZE_T nread;

#ifdef _WIN64

    ULONG_PTR wow64_peb = 0;
    if (g_NtQueryInformationProcess) {
        g_NtQueryInformationProcess(hProcess, ProcessWow64Information,
                                    &wow64_peb, sizeof(wow64_peb), NULL);
    }

    if (wow64_peb != 0) {
        g_is_32bit_target = 1;
        printf("[*] Target architecture: x86 (32-bit, WOW64)\n");
        printf("[*] WOW64 PEB at 0x%llX\n", (unsigned long long)wow64_peb);

        DWORD base32 = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(wow64_peb + 0x08),
                              &base32, sizeof(base32), &nread) && nread == 4) {
            *out_image_base = (ULONG_PTR)base32;
            printf("[+] ImageBase: 0x%08X\n", base32);
            return 1;
        }

        printf("[!] PEB read failed, trying default 0x00400000...\n");
        BYTE probe[2];
        if (ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)0x400000,
                              probe, 2, &nread) && probe[0] == 'M' && probe[1] == 'Z') {
            *out_image_base = 0x400000;
            printf("[+] ImageBase (fallback): 0x00400000\n");
            return 1;
        }
        return 0;
    }

    g_is_32bit_target = 0;
    printf("[*] Target architecture: x64 (64-bit, native)\n");

    MY_PROCESS_BASIC_INFORMATION pbi;
    memset(&pbi, 0, sizeof(pbi));
    NTSTATUS status = 0;
    if (g_NtQueryInformationProcess) {
        status = g_NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                             &pbi, sizeof(pbi), NULL);
    }

    if (NT_SUCCESS(status) && pbi.PebBaseAddress != NULL) {
        ULONG_PTR peb_addr = (ULONG_PTR)pbi.PebBaseAddress;
        printf("[*] PEB at 0x%llX\n", (unsigned long long)peb_addr);

        ULONGLONG base64 = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(peb_addr + 0x10),
                              &base64, sizeof(base64), &nread) && nread == 8) {
            *out_image_base = (ULONG_PTR)base64;
            printf("[+] ImageBase: 0x%llX\n", (unsigned long long)base64);
            return 1;
        }
    }

    printf("[!] PEB read failed, trying defaults...\n");
    BYTE probe[2];
    if (ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)0x140000000ULL,
                          probe, 2, &nread) && probe[0] == 'M' && probe[1] == 'Z') {
        *out_image_base = 0x140000000ULL;
        printf("[+] ImageBase (fallback): 0x0000000140000000\n");
        return 1;
    }
    if (ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)0x400000,
                          probe, 2, &nread) && probe[0] == 'M' && probe[1] == 'Z') {
        *out_image_base = 0x400000;
        printf("[+] ImageBase (fallback): 0x00400000\n");
        return 1;
    }
    return 0;

#else
    g_is_32bit_target = 1;
    printf("[*] Target architecture: x86 (32-bit)\n");

    MY_PROCESS_BASIC_INFORMATION pbi;
    memset(&pbi, 0, sizeof(pbi));
    NTSTATUS status = 0;
    if (g_NtQueryInformationProcess) {
        status = g_NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                             &pbi, sizeof(pbi), NULL);
    }

    if (NT_SUCCESS(status) && pbi.PebBaseAddress != NULL) {
        ULONG_PTR peb_addr = (ULONG_PTR)pbi.PebBaseAddress;
        printf("[*] PEB at 0x%08X\n", (unsigned)peb_addr);

        DWORD base32 = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(peb_addr + 0x08),
                              &base32, sizeof(base32), &nread) && nread == 4) {
            *out_image_base = (ULONG_PTR)base32;
            printf("[+] ImageBase: 0x%08X\n", base32);
            return 1;
        }
    }

    printf("[!] PEB read failed, trying default 0x00400000...\n");
    BYTE probe[2];
    if (ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)0x400000,
                          probe, 2, &nread) && probe[0] == 'M' && probe[1] == 'Z') {
        *out_image_base = 0x400000;
        printf("[+] ImageBase (fallback): 0x00400000\n");
        return 1;
    }
    return 0;

#endif
}

static int read_pe_sections(HANDLE hProc, ULONG_PTR base)
{
    BYTE hdr[4096];
    SIZE_T nread;

    if (!ReadProcessMemory(hProc, (LPCVOID)base, hdr, sizeof(hdr), &nread) || nread < 256)
        return 0;

    if (hdr[0] != 'M' || hdr[1] != 'Z') return 0;

    DWORD pe_off = *(DWORD*)(hdr + 0x3C);
    if (pe_off + 256 > sizeof(hdr)) return 0;

    BYTE *pe = hdr + pe_off;
    if (*(DWORD*)pe != 0x00004550) return 0;

    WORD num_secs = *(WORD*)(pe + 6);
    WORD opt_size = *(WORD*)(pe + 20);
    BYTE *opt_hdr = pe + 24;

    g_pe_magic = *(WORD*)opt_hdr;
    if (g_pe_magic == PE32_MAGIC) {
        printf("[*] PE format: PE32 (32-bit)\n");
    } else if (g_pe_magic == PE32PLUS_MAGIC) {
        printf("[*] PE format: PE32+ (64-bit)\n");
    } else {
        printf("[!] Unknown PE magic: 0x%04X\n", g_pe_magic);
        return 0;
    }

    BYTE *sec_tbl = pe + 24 + opt_size;

    if (num_secs > MAX_SECTIONS) num_secs = MAX_SECTIONS;
    g_num_sections = 0;

    printf("[*] Sections (%d):\n", num_secs);
    for (int i = 0; i < num_secs; i++) {
        BYTE *s = sec_tbl + i * 40;
        SectionInfo *si = &g_sections[g_num_sections];
        memset(si, 0, sizeof(*si));
        memcpy(si->name, s, 8);
        si->name[8] = '\0';
        si->rva      = *(DWORD*)(s + 12);
        si->vsize    = *(DWORD*)(s + 8);
        si->raw_size = *(DWORD*)(s + 16);
        si->changed  = 0;

        ReadProcessMemory(hProc, (LPCVOID)(base + si->rva),
                          si->fingerprint, FINGERPRINT_SIZE, &nread);

        char dname[16];
        strncpy(dname, si->name, 15); dname[15] = '\0';
        for (int j = (int)strlen(dname) - 1; j >= 0 && dname[j] <= ' '; j--)
            dname[j] = '\0';
        if (dname[0] == '\0') sprintf(dname, "sec_%d", i);

        int nz = 0;
        for (int j = 0; j < FINGERPRINT_SIZE; j++)
            if (si->fingerprint[j] != 0) nz++;

        printf("    %-12s RVA=0x%08X VS=0x%08X RS=0x%08X fp_nz=%d\n",
               dname, si->rva, si->vsize, si->raw_size, nz);
        g_num_sections++;
    }
    return g_num_sections;
}

static int check_changes(HANDLE hProc, ULONG_PTR base)
{
    int total = 0;
    SIZE_T nread;
    for (int i = 0; i < g_num_sections; i++) {
        SectionInfo *si = &g_sections[i];
        if (si->changed || si->vsize == 0) continue;
        BYTE current[FINGERPRINT_SIZE];
        if (!ReadProcessMemory(hProc, (LPCVOID)(base + si->rva),
                               current, FINGERPRINT_SIZE, &nread))
            continue;
        if (memcmp(current, si->fingerprint, FINGERPRINT_SIZE) != 0) {
            si->changed = 1;
            total++;
            printf("[!] DECRYPTION: section '%s' at " ADDR_FMT "\n",
                   si->name, ADDR_CAST(base + si->rva));
            printf("    Before: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   si->fingerprint[0], si->fingerprint[1], si->fingerprint[2], si->fingerprint[3],
                   si->fingerprint[4], si->fingerprint[5], si->fingerprint[6], si->fingerprint[7]);
            printf("    After:  %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   current[0], current[1], current[2], current[3],
                   current[4], current[5], current[6], current[7]);
        }
    }
    return total;
}

static int dump_section(HANDLE hProc, ULONG_PTR base, SectionInfo *si, int idx)
{
    if (si->vsize == 0) return 0;
    char sname[16];
    strncpy(sname, si->name, 15); sname[15] = '\0';
    for (int i = 0; sname[i]; i++) {
        char c = sname[i];
        if (c == '.' || c == '/' || c == '\\' || c == ':' || c == '*' ||
            c == '?' || c == '<' || c == '>' || c == '|' || c <= ' ')
            sname[i] = '_';
    }
    if (sname[0] == '\0') sprintf(sname, "sec%d", idx);

    char fname[MAX_PATH];
    char addr_str[32];
    snprintf(addr_str, sizeof(addr_str), ADDR_FMT, ADDR_CAST(base + si->rva));
    snprintf(fname, sizeof(fname), "%s\\%s_%s.bin", g_output_dir, sname, addr_str);

    DWORD dump_size = si->vsize;
    if (dump_size > 64 * 1024 * 1024) dump_size = 64 * 1024 * 1024;

    BYTE *buf = (BYTE*)malloc(dump_size);
    if (!buf) return 0;
    memset(buf, 0, dump_size);

    SIZE_T nread;
    DWORD chunk = 0x1000;
    for (DWORD off = 0; off < dump_size; off += chunk) {
        DWORD sz = (dump_size - off < chunk) ? (dump_size - off) : chunk;
        ReadProcessMemory(hProc, (LPCVOID)(base + si->rva + off),
                          buf + off, sz, &nread);
    }

    FILE *f = fopen(fname, "wb");
    if (!f) { free(buf); return 0; }
    fwrite(buf, 1, dump_size, f);
    fclose(f);

    int nz = 0;
    DWORD check = (dump_size < 4096) ? dump_size : 4096;
    for (DWORD j = 0; j < check; j++)
        if (buf[j] != 0 && buf[j] != 0xFF) nz++;

    printf("[+] %-12s %8u bytes -> %s  [nz=%d]\n", si->name, dump_size, fname, nz);
    free(buf);
    return 1;
}

static void dump_full_image(HANDLE hProc, ULONG_PTR base, DWORD soi, const char *name)
{
    if (soi == 0 || soi > 256 * 1024 * 1024) return;

    const char *basename = name;
    const char *p;
    p = strrchr(name, '\\'); if (p) basename = p + 1;
    p = strrchr(basename, '/'); if (p) basename = p + 1;

    char fname[MAX_PATH];
    snprintf(fname, sizeof(fname), "%s\\%s_unpacked.exe", g_output_dir, basename);

    BYTE *buf = (BYTE*)malloc(soi);
    if (!buf) return;
    memset(buf, 0, soi);

    SIZE_T nread;
    DWORD chunk = 0x1000;
    for (DWORD off = 0; off < soi; off += chunk) {
        DWORD sz = (soi - off < chunk) ? (soi - off) : chunk;
        ReadProcessMemory(hProc, (LPCVOID)(base + off), buf + off, sz, &nread);
    }

    DWORD pe_off = *(DWORD*)(buf + 0x3C);
    if (pe_off + 256 < soi) {
        BYTE *opt = buf + pe_off + 24;
        WORD magic = *(WORD*)opt;

        if (magic == PE32_MAGIC) {
            *(DWORD*)(opt + 28) = (DWORD)base;
        } else if (magic == PE32PLUS_MAGIC) {
            *(ULONGLONG*)(opt + 24) = (ULONGLONG)base;
        }

        WORD ns = *(WORD*)(buf + pe_off + 6);
        WORD os = *(WORD*)(buf + pe_off + 20);
        BYTE *st = buf + pe_off + 24 + os;
        for (int i = 0; i < ns && i < MAX_SECTIONS; i++) {
            BYTE *s = st + i * 40;
            DWORD vs  = *(DWORD*)(s + 8);
            DWORD rva = *(DWORD*)(s + 12);
            *(DWORD*)(s + 16) = vs;
            *(DWORD*)(s + 20) = rva;
        }
    }

    FILE *f = fopen(fname, "wb");
    if (f) { fwrite(buf, 1, soi, f); fclose(f); }
    printf("[+] Full PE: %s (%u bytes, %s)\n", fname, (unsigned)soi,
           (g_pe_magic == PE32PLUS_MAGIC) ? "PE32+" : "PE32");
    free(buf);
}

static void scan_process_strings(HANDLE hProc, ULONG_PTR image_base)
{
    printf("\n[*] Scanning process memory for config strings & IOCs...\n");

    char report_path[MAX_PATH];
    snprintf(report_path, sizeof(report_path), "%s\\extracted_strings.txt", g_output_dir);
    FILE *report = fopen(report_path, "w");
    if (!report) {
        printf("[-] Cannot create string report\n");
        return;
    }

    fprintf(report, "=== Themida Dumper v4 (Universal) - Extracted Strings ===\n");
    fprintf(report, "Target architecture: %s\n\n", g_is_32bit_target ? "x86" : "x64");

    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0x10000;
    int total_regions = 0;
    int total_strings = 0;
    int ioc_count = 0;

#ifdef _WIN64
    ULONG_PTR max_addr = g_is_32bit_target ? (ULONG_PTR)0x7FFF0000ULL : (ULONG_PTR)0x7FFFFFFFFFFFULL;
#else
    ULONG_PTR max_addr = (ULONG_PTR)0x7FFF0000;
#endif

    BYTE *page_buf = (BYTE*)malloc(0x10000);
    if (!page_buf) { fclose(report); return; }

    while (addr < max_addr) {
        if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)))
            break;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)))
        {
            ULONG_PTR region_base = (ULONG_PTR)mbi.BaseAddress;
            SIZE_T region_size = mbi.RegionSize;

            if (region_size > 4 * 1024 * 1024)
                region_size = 4 * 1024 * 1024;

            total_regions++;

            for (SIZE_T off = 0; off < region_size; off += 0x10000) {
                SIZE_T read_sz = (region_size - off < 0x10000) ? (region_size - off) : 0x10000;
                SIZE_T nread = 0;
                if (!ReadProcessMemory(hProc, (LPCVOID)(region_base + off),
                                       page_buf, read_sz, &nread) || nread == 0)
                    continue;

                int str_start = -1;
                for (SIZE_T i = 0; i <= nread; i++) {
                    int printable = (i < nread) &&
                                    (page_buf[i] >= 0x20 && page_buf[i] < 0x7F);
                    if (printable && str_start < 0)
                        str_start = (int)i;
                    else if (!printable && str_start >= 0) {
                        int len = (int)i - str_start;
                        if (len >= MIN_STR_LEN && len < MAX_STR_LEN) {
                            char tmp[MAX_STR_LEN];
                            memcpy(tmp, page_buf + str_start, len);
                            tmp[len] = '\0';
                            const char *cat = categorize_string(tmp);
                            if (cat) {
                                ULONG_PTR saddr = region_base + off + str_start;
                                fprintf(report, "[%-12s] " ADDR_FMT ": %s\n",
                                        cat, ADDR_CAST(saddr), tmp);
                                ioc_count++;
                                if (strcmp(cat, "btc_wallet") == 0 ||
                                    strcmp(cat, "onion_url") == 0 ||
                                    strcmp(cat, "url") == 0 ||
                                    strcmp(cat, "email") == 0 ||
                                    strcmp(cat, "ransom") == 0 ||
                                    strcmp(cat, "mutex") == 0) {
                                    printf("    [%s] %s\n", cat, tmp);
                                }
                            }
                            total_strings++;
                        }
                        str_start = -1;
                    }
                }

                str_start = -1;
                for (SIZE_T i = 0; i + 1 <= nread; i += 2) {
                    int printable = (i + 1 < nread) &&
                                    (page_buf[i] >= 0x20 && page_buf[i] < 0x7F) &&
                                    (page_buf[i + 1] == 0);
                    if (printable && str_start < 0)
                        str_start = (int)i;
                    else if (!printable && str_start >= 0) {
                        int wlen = ((int)i - str_start) / 2;
                        if (wlen >= MIN_STR_LEN && wlen < MAX_STR_LEN) {
                            char tmp[MAX_STR_LEN];
                            for (int k = 0; k < wlen; k++)
                                tmp[k] = page_buf[str_start + k * 2];
                            tmp[wlen] = '\0';
                            const char *cat = categorize_string(tmp);
                            if (cat) {
                                ULONG_PTR saddr = region_base + off + str_start;
                                fprintf(report, "[%-12s] " ADDR_FMT " W: %s\n",
                                        cat, ADDR_CAST(saddr), tmp);
                                ioc_count++;
                                if (strcmp(cat, "btc_wallet") == 0 ||
                                    strcmp(cat, "onion_url") == 0 ||
                                    strcmp(cat, "url") == 0 ||
                                    strcmp(cat, "email") == 0 ||
                                    strcmp(cat, "ransom") == 0 ||
                                    strcmp(cat, "extension") == 0 ||
                                    strcmp(cat, "mutex") == 0) {
                                    printf("    [%s] W: %s\n", cat, tmp);
                                }
                            }
                            total_strings++;
                        }
                        str_start = -1;
                    }
                }
            }
        }

        ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    fprintf(report, "\n=== Summary ===\n");
    fprintf(report, "Target: %s\n", g_is_32bit_target ? "x86 (32-bit)" : "x64 (64-bit)");
    fprintf(report, "Regions scanned: %d\n", total_regions);
    fprintf(report, "Total categorized strings: %d\n", total_strings);
    fprintf(report, "IOCs found: %d\n", ioc_count);
    fclose(report);
    free(page_buf);

    printf("[+] String scan: %d regions, %d IOCs -> %s\n",
           total_regions, ioc_count, report_path);
}

static void capture_dropped_files(const char *target_dir)
{
    printf("\n[*] Scanning for dropped files (ransom notes)...\n");

    WIN32_FIND_DATAA fd;
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", target_dir);

    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    int found = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        const char *name = fd.cFileName;

        int is_note = 0;
        if (strstr(name, "README") || strstr(name, "readme") ||
            strstr(name, "DECRYPT") || strstr(name, "decrypt") ||
            strstr(name, "RESTORE") || strstr(name, "restore") ||
            strstr(name, "RECOVER") || strstr(name, "recover") ||
            strstr(name, "RANSOM") || strstr(name, "ransom") ||
            strstr(name, "HOW_TO") || strstr(name, "how_to") ||
            strstr(name, "HowTo") || strstr(name, "HELP") ||
            strstr(name, ".hta") || strstr(name, ".html"))
            is_note = 1;
        if (strstr(name, ".txt") || strstr(name, ".TXT"))
            is_note = 1;

        if (is_note) {
            char src[MAX_PATH], dst[MAX_PATH];
            snprintf(src, sizeof(src), "%s\\%s", target_dir, name);
            snprintf(dst, sizeof(dst), "%s\\%s", g_output_dir, name);

            if (CopyFileA(src, dst, FALSE)) {
                printf("[+] Captured: %s (%lu bytes)\n", name, fd.nFileSizeLow);
                found++;
            }
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    if (found == 0) printf("    No ransom notes found in %s\n", target_dir);
}

static void dump_all(HANDLE hProc, ULONG_PTR base, const char *target_name)
{
    printf("\n[*] Dumping all sections:\n");
    for (int i = 0; i < g_num_sections; i++)
        dump_section(hProc, base, &g_sections[i], i);

    BYTE hdr[512];
    SIZE_T nr;
    ReadProcessMemory(hProc, (LPCVOID)base, hdr, sizeof(hdr), &nr);
    DWORD pe_off = *(DWORD*)(hdr + 0x3C);
    DWORD soi = *(DWORD*)(hdr + pe_off + 24 + 56);
    dump_full_image(hProc, base, soi, target_name);

    scan_process_strings(hProc, base);
}

static void kill_monitor_processes(int kill_vmtools)
{
    printf("[*] Killing monitor programs Themida detects...\n");
    const char *monitors[] = {
        "procmon.exe", "procmon64.exe", "Procmon.exe",
        "procexp.exe", "procexp64.exe",
        "wireshark.exe", "Wireshark.exe",
        "fiddler.exe", "Fiddler.exe",
        "tcpview.exe", "tcpview64.exe",
        "autoruns.exe", "autoruns64.exe",
        "filemon.exe", "regmon.exe",
        "ProcessHacker.exe", "processhacker.exe",
        "pestudio.exe", "PEStudio.exe",
        "x64dbg.exe", "x32dbg.exe", "ollydbg.exe",
        "idaq.exe", "idaq64.exe", "ida.exe", "ida64.exe",
        "dumpcap.exe", "rawshark.exe",
        "HookExplorer.exe", "ImportREC.exe",
        "SysInspector.exe", "SysAnalyzer.exe",
        "Sniff_hit.exe", "joeboxcontrol.exe", "joeboxserver.exe",
        "ResourceHacker.exe", "BehaviorDumper.exe",
        "idag.exe", "idag64.exe", "immunitydebugger.exe",
        "agent.exe", "analyzer.exe", "cuckoomon.exe",
        "python.exe", "pythonw.exe",
        "apimonitor.exe", "apimonitor-x86.exe", "apimonitor-x64.exe",
        "OLLYDBG.EXE", "windbg.exe", "dbgview.exe",
        "Dbgview.exe", "DebugView.exe",
        "regshot.exe", "Regshot-x86-Unicode.exe",
        "fakenet.exe", "netmon.exe",
        "petools.exe", "LordPE.exe",
        "SysinternalsSuite.exe",
        NULL
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            for (int i = 0; monitors[i]; i++) {
                if (_stricmp(pe.szExeFile, monitors[i]) == 0) {
                    HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hp) {
                        TerminateProcess(hp, 0);
                        CloseHandle(hp);
                        printf("    Killed: %s (PID %u)\n", pe.szExeFile, pe.th32ProcessID);
                    }
                    break;
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    if (kill_vmtools) {
        printf("[*] Killing VMware/VBox tools (--kill-vmtools enabled)...\n");
        printf("    WARNING: Shared folders and clipboard will stop working!\n");

        const char *vm_procs[] = {
            "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
            "vmacthlp.exe", "VBoxService.exe", "VBoxTray.exe",
            "VGAuthService.exe", NULL
        };
        HANDLE snap2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap2 != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe2;
            pe2.dwSize = sizeof(pe2);
            if (Process32First(snap2, &pe2)) {
                do {
                    for (int i = 0; vm_procs[i]; i++) {
                        if (_stricmp(pe2.szExeFile, vm_procs[i]) == 0) {
                            HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pe2.th32ProcessID);
                            if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
                            printf("    Killed: %s\n", pe2.szExeFile);
                            break;
                        }
                    }
                } while (Process32Next(snap2, &pe2));
            }
            CloseHandle(snap2);
        }

        const char *vm_svcs[] = {
            "VMTools", "vm3dservice", "VGAuthService",
            "VMUSBArbService", "vmvss", "VBoxService", NULL
        };
        SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
        if (scm) {
            for (int i = 0; vm_svcs[i]; i++) {
                SC_HANDLE svc = OpenServiceA(scm, vm_svcs[i], SERVICE_STOP | SERVICE_QUERY_STATUS);
                if (svc) {
                    SERVICE_STATUS ss;
                    if (ControlService(svc, SERVICE_CONTROL_STOP, &ss))
                        printf("    Stopped service: %s\n", vm_svcs[i]);
                    CloseServiceHandle(svc);
                }
            }
            CloseServiceHandle(scm);
        }
    } else {
        printf("[*] VMware Tools: kept running (use --kill-vmtools to disable)\n");
    }
}

static void enable_debug_privilege(void)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        if (GetLastError() == ERROR_SUCCESS)
            printf("[+] SeDebugPrivilege enabled\n");
    }
    CloseHandle(hToken);
}

#define SVC_TEMP_NAME "ThemidaDumpSvc"

static HANDLE launch_service_dll(const char *dll_path, ULONG_PTR *out_dll_base, DWORD *out_pid)
{
    *out_dll_base = 0;
    *out_pid = 0;

    char abs_path[MAX_PATH];
    GetFullPathNameA(dll_path, MAX_PATH, abs_path, NULL);

    char sys_dir[MAX_PATH];
    GetSystemDirectoryA(sys_dir, MAX_PATH);

    printf("[*] Service DLL mode: creating temporary service...\n");

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        printf("[-] OpenSCManager failed (error %u). Run as Administrator!\n",
               (unsigned)GetLastError());
        return NULL;
    }

    SC_HANDLE old_svc = OpenServiceA(scm, SVC_TEMP_NAME, SERVICE_ALL_ACCESS);
    if (old_svc) {
        SERVICE_STATUS ss;
        ControlService(old_svc, SERVICE_CONTROL_STOP, &ss);
        Sleep(500);
        DeleteService(old_svc);
        CloseServiceHandle(old_svc);
        Sleep(500);
    }

    char svchost_cmd[MAX_PATH];
    snprintf(svchost_cmd, sizeof(svchost_cmd),
             "%s\\svchost.exe -k %s", sys_dir, SVC_TEMP_NAME);
    printf("[*] svchost cmd: %s\n", svchost_cmd);

    SC_HANDLE svc = CreateServiceA(
        scm, SVC_TEMP_NAME, SVC_TEMP_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_SHARE_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        svchost_cmd,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!svc) {
        DWORD err = GetLastError();
        printf("[-] CreateService failed (error %u)\n", (unsigned)err);
        if (err == 1073) printf("    Service already exists. Delete it: sc delete %s\n", SVC_TEMP_NAME);
        CloseServiceHandle(scm);
        return NULL;
    }
    printf("[+] Service created: %s\n", SVC_TEMP_NAME);

    char reg_path[MAX_PATH];
    snprintf(reg_path, sizeof(reg_path),
             "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", SVC_TEMP_NAME);
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, reg_path, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "ServiceDll", 0, REG_EXPAND_SZ,
                       (const BYTE*)abs_path, (DWORD)(strlen(abs_path) + 1));
        RegCloseKey(hKey);
        printf("[+] ServiceDll: %s\n", abs_path);
    }

    HKEY hSvcHost;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
                      0, KEY_SET_VALUE, &hSvcHost) == ERROR_SUCCESS) {
        int name_len = (int)strlen(SVC_TEMP_NAME);
        char group_val[256];
        memset(group_val, 0, sizeof(group_val));
        memcpy(group_val, SVC_TEMP_NAME, name_len);
        RegSetValueExA(hSvcHost, SVC_TEMP_NAME, 0, REG_MULTI_SZ,
                       (const BYTE*)group_val, (DWORD)(name_len + 2));
        RegCloseKey(hSvcHost);
        printf("[+] Svchost group registered\n");
    }

    printf("[*] Starting service...\n");
    BOOL started = StartServiceA(svc, 0, NULL);
    if (!started) {
        DWORD err = GetLastError();
        printf("[*] StartService error %u", (unsigned)err);
        if (err == 1053) printf(" (timeout - normal for malware)");
        else if (err == 1056) printf(" (already running)");
        else if (err == 1067) printf(" (process terminated)");
        printf("\n");
    } else {
        printf("[+] StartService succeeded\n");
    }

    Sleep(1000);

    SERVICE_STATUS_PROCESS ssp;
    DWORD needed = 0;
    DWORD service_pid = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                             (LPBYTE)&ssp, sizeof(ssp), &needed)) {
        service_pid = ssp.dwProcessId;
        printf("[+] Service PID: %u  State: %u\n", service_pid, ssp.dwCurrentState);
    }

    HANDLE hProc = NULL;
    if (service_pid != 0) {
        hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, service_pid);
        if (!hProc) {
            printf("[-] OpenProcess PID=%u failed (error %u)\n",
                   service_pid, (unsigned)GetLastError());
        } else {
            printf("[+] Attached to svchost PID=%u\n", service_pid);

            const char *dll_basename = abs_path;
            const char *p;
            p = strrchr(dll_basename, '\\'); if (p) dll_basename = p + 1;
            p = strrchr(dll_basename, '/');  if (p) dll_basename = p + 1;

            HANDLE modSnap = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, service_pid);
            if (modSnap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32W me;
                me.dwSize = sizeof(me);
                if (Module32FirstW(modSnap, &me)) {
                    do {
                        char mod_path[MAX_PATH], mod_name[MAX_PATH];
                        WideCharToMultiByte(CP_ACP, 0, me.szExePath, -1,
                                           mod_path, MAX_PATH, NULL, NULL);
                        WideCharToMultiByte(CP_ACP, 0, me.szModule, -1,
                                           mod_name, MAX_PATH, NULL, NULL);
                        if (_stricmp(mod_path, abs_path) == 0 ||
                            _stricmp(mod_name, dll_basename) == 0) {
                            *out_dll_base = (ULONG_PTR)me.modBaseAddr;
                            *out_pid = service_pid;
                            printf("[+] Found DLL at " ADDR_FMT "\n", ADDR_CAST(*out_dll_base));
                            break;
                        }
                    } while (Module32NextW(modSnap, &me));
                }
                CloseHandle(modSnap);
            }

            if (*out_dll_base == 0) {
                printf("[!] DLL not found by name. Scanning non-system modules...\n");
                modSnap = CreateToolhelp32Snapshot(
                    TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, service_pid);
                if (modSnap != INVALID_HANDLE_VALUE) {
                    MODULEENTRY32W me2;
                    me2.dwSize = sizeof(me2);
                    if (Module32FirstW(modSnap, &me2)) {
                        do {
                            char mod_path[MAX_PATH];
                            WideCharToMultiByte(CP_ACP, 0, me2.szExePath, -1,
                                               mod_path, MAX_PATH, NULL, NULL);
                            if (_strnicmp(mod_path, sys_dir, strlen(sys_dir)) == 0) continue;
                            if (strstr(mod_path, "\\Windows\\") != NULL) continue;
                            *out_dll_base = (ULONG_PTR)me2.modBaseAddr;
                            *out_pid = service_pid;
                            printf("[+] Non-system module: %s at " ADDR_FMT "\n",
                                   mod_path, ADDR_CAST(*out_dll_base));
                            break;
                        } while (Module32NextW(modSnap, &me2));
                    }
                    CloseHandle(modSnap);
                }
            }
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (!hProc || *out_dll_base == 0) {
        printf("[-] Could not find DLL in service process\n");
        return NULL;
    }
    return hProc;
}

static void cleanup_temp_service(void)
{
    printf("[*] Cleaning up temporary service...\n");
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceA(scm, SVC_TEMP_NAME, SERVICE_ALL_ACCESS);
    if (svc) {
        SERVICE_STATUS ss;
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        Sleep(1000);
        if (DeleteService(svc)) printf("[+] Service deleted\n");
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);

    HKEY hSvcHost;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
                      0, KEY_SET_VALUE, &hSvcHost) == ERROR_SUCCESS) {
        RegDeleteValueA(hSvcHost, SVC_TEMP_NAME);
        RegCloseKey(hSvcHost);
    }
}

static const char* get_basename(const char *path)
{
    const char *name = path;
    const char *p;
    p = strrchr(name, '\\'); if (p) name = p + 1;
    p = strrchr(name, '/');  if (p) name = p + 1;
    return name;
}

static void get_parent_dir(const char *path, char *out, int out_size)
{
    strncpy(out, path, out_size - 1);
    out[out_size - 1] = '\0';
    char *last_slash = strrchr(out, '\\');
    char *last_fslash = strrchr(out, '/');
    if (last_fslash > last_slash) last_slash = last_fslash;
    if (last_slash) *last_slash = '\0';
    else strcpy(out, ".");
}

static void build_output_dir(const char *target_path)
{
    const char *basename = get_basename(target_path);
    char parent[MAX_PATH];
    get_parent_dir(target_path, parent, sizeof(parent));

    snprintf(g_output_dir, sizeof(g_output_dir),
             "%s\\themida_dump_%s", parent, basename);
}

#define ZIP_LOCAL_SIG       0x04034b50
#define ZIP_CENTRAL_SIG     0x02014b50
#define ZIP_END_SIG         0x06054b50
#define ZIP_ENC_HDR_SIZE    12
#define ZIP_MAX_FILES       128

static DWORD g_crc_table[256];
static int   g_crc_ready = 0;

static void crc32_init(void)
{
    if (g_crc_ready) return;
    for (DWORD i = 0; i < 256; i++) {
        DWORD c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        g_crc_table[i] = c;
    }
    g_crc_ready = 1;
}

static DWORD crc32_update(DWORD crc, const BYTE *buf, DWORD len)
{
    crc ^= 0xFFFFFFFF;
    for (DWORD i = 0; i < len; i++)
        crc = g_crc_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

typedef struct { DWORD k0, k1, k2; } ZCKeys;

static void zc_update(ZCKeys *k, BYTE c)
{
    k->k0 = g_crc_table[(k->k0 ^ c) & 0xFF] ^ (k->k0 >> 8);
    k->k1 = (k->k1 + (k->k0 & 0xFF)) * 134775813u + 1;
    k->k2 = g_crc_table[(k->k2 ^ (BYTE)(k->k1 >> 24)) & 0xFF] ^ (k->k2 >> 8);
}

static BYTE zc_stream_byte(ZCKeys *k)
{
    WORD t = (WORD)(k->k2 | 2);
    return (BYTE)((t * (t ^ 1)) >> 8);
}

static BYTE zc_encrypt(ZCKeys *k, BYTE plain)
{
    BYTE cipher = plain ^ zc_stream_byte(k);
    zc_update(k, plain);
    return cipher;
}

static void zc_init_password(ZCKeys *k, const char *pw)
{
    k->k0 = 305419896u;
    k->k1 = 591751049u;
    k->k2 = 878082192u;
    while (*pw) zc_update(k, (BYTE)*pw++);
}

static void write16(FILE *f, WORD v)  { fwrite(&v, 2, 1, f); }
static void write32(FILE *f, DWORD v) { fwrite(&v, 4, 1, f); }

static void get_dos_datetime(WORD *dos_date, WORD *dos_time)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    *dos_time = (WORD)((st.wSecond / 2) | (st.wMinute << 5) | (st.wHour << 11));
    *dos_date = (WORD)(st.wDay | (st.wMonth << 5) | ((st.wYear - 1980) << 9));
}

typedef struct {
    char  name[MAX_PATH];
    WORD  name_len;
    DWORD crc;
    DWORD comp_size;
    DWORD raw_size;
    DWORD local_offset;
    WORD  dos_date;
    WORD  dos_time;
} ZipFileEntry;

static char g_zip_path[MAX_PATH] = "";

static int create_password_zip(const char *dump_dir)
{
    char zip_path[MAX_PATH];
    snprintf(zip_path, sizeof(zip_path), "%s.dat", dump_dir);

    printf("\n[*] Creating password-protected archive (pass: virus)...\n");
    printf("    Extension: .dat (safe from ransomware, rename to .zip to extract)\n");

    crc32_init();
    srand((unsigned)GetTickCount());

    ZipFileEntry entries[ZIP_MAX_FILES];
    int num_entries = 0;

    WIN32_FIND_DATAA fd;
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", dump_dir);
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("[-] No files to zip in %s\n", dump_dir);
        return 0;
    }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (num_entries >= ZIP_MAX_FILES) break;
        ZipFileEntry *e = &entries[num_entries];
        strncpy(e->name, fd.cFileName, MAX_PATH - 1);
        e->name[MAX_PATH - 1] = '\0';
        e->name_len = (WORD)strlen(e->name);
        e->raw_size = fd.nFileSizeLow;
        e->comp_size = e->raw_size + ZIP_ENC_HDR_SIZE;
        e->crc = 0;
        e->local_offset = 0;
        get_dos_datetime(&e->dos_date, &e->dos_time);
        num_entries++;
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    if (num_entries == 0) {
        printf("[-] No files found to zip\n");
        return 0;
    }

    FILE *zf = fopen(zip_path, "wb");
    if (!zf) {
        printf("[-] Cannot create %s\n", zip_path);
        return 0;
    }

    BYTE io_buf[8192];
    const char *password = "virus";

    for (int i = 0; i < num_entries; i++) {
        ZipFileEntry *e = &entries[i];

        char src_path[MAX_PATH];
        snprintf(src_path, sizeof(src_path), "%s\\%s", dump_dir, e->name);

        FILE *sf = fopen(src_path, "rb");
        if (!sf) continue;
        DWORD crc = 0;
        for (;;) {
            DWORD n = (DWORD)fread(io_buf, 1, sizeof(io_buf), sf);
            if (n == 0) break;
            crc = crc32_update(crc, io_buf, n);
        }
        e->crc = crc;

        e->local_offset = (DWORD)ftell(zf);

        write32(zf, ZIP_LOCAL_SIG);
        write16(zf, 20);
        write16(zf, 0x0001);
        write16(zf, 0);
        write16(zf, e->dos_time);
        write16(zf, e->dos_date);
        write32(zf, e->crc);
        write32(zf, e->comp_size);
        write32(zf, e->raw_size);
        write16(zf, e->name_len);
        write16(zf, 0);
        fwrite(e->name, 1, e->name_len, zf);

        ZCKeys keys;
        zc_init_password(&keys, password);

        BYTE enc_hdr[ZIP_ENC_HDR_SIZE];
        for (int j = 0; j < 11; j++)
            enc_hdr[j] = zc_encrypt(&keys, (BYTE)(rand() & 0xFF));
        enc_hdr[11] = zc_encrypt(&keys, (BYTE)(e->crc >> 24));
        fwrite(enc_hdr, 1, ZIP_ENC_HDR_SIZE, zf);

        fseek(sf, 0, SEEK_SET);
        for (;;) {
            DWORD n = (DWORD)fread(io_buf, 1, sizeof(io_buf), sf);
            if (n == 0) break;
            for (DWORD j = 0; j < n; j++)
                io_buf[j] = zc_encrypt(&keys, io_buf[j]);
            fwrite(io_buf, 1, n, zf);
        }
        fclose(sf);
    }

    DWORD cd_offset = (DWORD)ftell(zf);
    for (int i = 0; i < num_entries; i++) {
        ZipFileEntry *e = &entries[i];
        write32(zf, ZIP_CENTRAL_SIG);
        write16(zf, 20);
        write16(zf, 20);
        write16(zf, 0x0001);
        write16(zf, 0);
        write16(zf, e->dos_time);
        write16(zf, e->dos_date);
        write32(zf, e->crc);
        write32(zf, e->comp_size);
        write32(zf, e->raw_size);
        write16(zf, e->name_len);
        write16(zf, 0);
        write16(zf, 0);
        write16(zf, 0);
        write16(zf, 0);
        write32(zf, 0x00000020);
        write32(zf, e->local_offset);
        fwrite(e->name, 1, e->name_len, zf);
    }
    DWORD cd_size = (DWORD)ftell(zf) - cd_offset;

    write32(zf, ZIP_END_SIG);
    write16(zf, 0);
    write16(zf, 0);
    write16(zf, (WORD)num_entries);
    write16(zf, (WORD)num_entries);
    write32(zf, cd_size);
    write32(zf, cd_offset);
    write16(zf, 0);

    DWORD zip_size = (DWORD)ftell(zf);
    fclose(zf);

    strncpy(g_zip_path, zip_path, MAX_PATH - 1);
    printf("[+] Archive created: %s\n", zip_path);
    printf("    %d files, %u bytes\n", num_entries, (unsigned)zip_size);
    printf("    Password: virus\n");
    printf("    To extract: rename .dat -> .zip, then unzip with password\n");
    return 1;
}

int main(int argc, char *argv[])
{
    printf("=======================================================\n");
    printf("  Themida Section Dumper v4.0 (Universal)\n");
    printf("  Supports 32-bit AND 64-bit PE targets\n");
    printf("  + Heap string scanner + IOC extraction\n");
    printf("  Drag & drop a sample onto this exe to start!\n");
    printf("=======================================================\n\n");

    int kill_vmtools = 0;
    int custom_output = 0;

    if (argc < 2) {
        printf("Usage: %s <target.exe|target.dll> [options]\n\n", argv[0]);
        printf("  Drag & drop a Themida-protected PE onto this exe,\n");
        printf("  or run from command line.\n\n");
        printf("  Output folder is auto-created next to the sample:\n");
        printf("    themida_dump_{sample_filename}\\\n\n");
        printf("Options:\n");
        printf("  --dll-export=Name   For DLL targets: specify export to call\n");
        printf("                      (default: DllRegisterServer)\n");
        printf("  --kill-vmtools      Kill VMware/VBox Tools (disables shared folders!)\n");
        printf("                      Copy this tool to the VM FIRST.\n\n");
        printf("DLL examples:\n");
        printf("  %s malware.dll\n", argv[0]);
        printf("  %s malware.dll --dll-export=ServiceMain\n", argv[0]);
        printf("  %s malware.dll --dll-export=#1\n", argv[0]);
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        g_NtQueryInformationProcess = (pfnNtQueryInformationProcess)
            GetProcAddress(hNtdll, "NtQueryInformationProcess");
    }
    if (!g_NtQueryInformationProcess) {
        printf("[-] FATAL: Cannot resolve NtQueryInformationProcess\n");
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }

    enable_debug_privilege();

    const char *target_exe = argv[1];
    for (int i = 2; i < argc; i++) {
        if (strncmp(argv[i], "--dll-export=", 13) == 0) {
            strncpy(g_dll_export, argv[i] + 13, sizeof(g_dll_export) - 1);
        } else if (strcmp(argv[i], "--kill-vmtools") == 0) {
            kill_vmtools = 1;
        }
    }

    char target_fullpath[MAX_PATH];
    if (GetFullPathNameA(target_exe, MAX_PATH, target_fullpath, NULL)) {
        target_exe = target_fullpath;
    }

    DWORD attr = GetFileAttributesA(target_exe);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        printf("[-] File not found: %s\n", target_exe);
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }

    build_output_dir(target_exe);
    CreateDirectoryA(g_output_dir, NULL);

    const char *ext = strrchr(target_exe, '.');
    if (ext && (_stricmp(ext, ".dll") == 0 || _stricmp(ext, ".ocx") == 0 ||
                _stricmp(ext, ".cpl") == 0)) {
        g_is_dll = 1;
    }

    printf("[*] Target: %s%s\n", get_basename(target_exe), g_is_dll ? " (DLL)" : " (EXE)");
    printf("[*] Output: %s\n", g_output_dir);

    if (g_is_dll && g_dll_export[0] == '\0') {
        printf("\n");
        printf("=======================================================\n");
        printf("  ERROR: DLL target requires --dll-export argument!\n");
        printf("=======================================================\n\n");
        printf("  DLLs cannot be drag-and-dropped. Run from command line:\n\n");
        printf("    %s %s --dll-export=ExportName\n\n", get_basename(argv[0]), get_basename(target_exe));
        printf("  Common exports:\n");
        printf("    --dll-export=DllRegisterServer   (regsvr32 DLLs)\n");
        printf("    --dll-export=ServiceMain         (service DLLs)\n");
        printf("    --dll-export=#1                  (ordinal exports)\n\n");
        printf("  Use a PE viewer (CFF Explorer, PE-bear, dumpbin /exports)\n");
        printf("  to check which export the DLL has.\n");
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }

    if (g_is_dll && (_stricmp(g_dll_export, "ServiceMain") == 0 ||
                     _stricmp(g_dll_export, "SvcMain") == 0)) {
        g_is_service_dll = 1;
    }

    if (g_is_dll)
        printf("[*] DLL export: %s%s\n", g_dll_export,
               g_is_service_dll ? " (service DLL mode)" : " (rundll32 mode)");
    printf("\n");

    kill_monitor_processes(kill_vmtools);

    char target_dir[MAX_PATH];
    get_parent_dir(target_exe, target_dir, sizeof(target_dir));

    if (g_is_service_dll) {
        ULONG_PTR svc_dll_base = 0;
        DWORD svc_pid = 0;
        HANDLE hProc = launch_service_dll(target_exe, &svc_dll_base, &svc_pid);
        if (!hProc) {
            printf("[-] Service DLL launch failed\n");
            cleanup_temp_service();
            printf("\nPress Enter to exit...");
            getchar();
            return 1;
        }
        g_image_base = svc_dll_base;

        if (!read_pe_sections(hProc, g_image_base)) {
            printf("[-] Cannot read PE sections\n");
            cleanup_temp_service();
            CloseHandle(hProc);
            printf("\nPress Enter to exit...");
            getchar();
            return 1;
        }

        printf("\n[*] Service DLL loaded. Dumping (already decrypted)...\n");
        dump_all(hProc, g_image_base, target_exe);
        capture_dropped_files(target_dir);
        capture_dropped_files(".");

        cleanup_temp_service();
        CloseHandle(hProc);

    } else {
        char cmdline[MAX_PATH * 2];
        if (g_is_dll) {
            snprintf(cmdline, sizeof(cmdline),
                     "rundll32.exe \"%s\",%s", target_exe, g_dll_export);
            printf("[*] DLL launch: %s\n", cmdline);
        } else {
            strncpy(cmdline, target_exe, sizeof(cmdline) - 1);
            cmdline[sizeof(cmdline) - 1] = '\0';
        }

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
        memset(&pi, 0, sizeof(pi));

        printf("[*] Launching as SUSPENDED...\n");
        if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                            CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            DWORD err = GetLastError();
            printf("[-] CreateProcess failed (error %u)\n", (unsigned)err);
            if (err == 740)
                printf("    Hint: Try running this tool as Administrator.\n");
            printf("\nPress Enter to exit...");
            getchar();
            return 1;
        }
        printf("[+] PID=%u TID=%u\n", pi.dwProcessId, pi.dwThreadId);

        if (!detect_target_architecture(pi.hProcess, &g_image_base)) {
            printf("[-] Cannot determine target architecture or image base\n");
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            printf("\nPress Enter to exit...");
            getchar();
            return 1;
        }

        if (!read_pe_sections(pi.hProcess, g_image_base)) {
            printf("[-] Cannot read PE sections\n");
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            printf("\nPress Enter to exit...");
            getchar();
            return 1;
        }

        printf("\n[*] Resuming process...\n");
        ResumeThread(pi.hThread);

        int ticks = 0, max_ticks = (MAX_MONITOR_SEC * 1000) / POLL_INTERVAL_MS;
        int dump_done = 0;

        while (!dump_done && ticks < max_ticks) {
            Sleep(POLL_INTERVAL_MS);
            ticks++;

            DWORD ec;
            int alive = (GetExitCodeProcess(pi.hProcess, &ec) && ec == STILL_ACTIVE);
            int changed = check_changes(pi.hProcess, g_image_base);

            if (changed > 0) {
                SuspendThread(pi.hThread);
                printf("[!] Decryption detected! Process SUSPENDED.\n");
                Sleep(500);
                ResumeThread(pi.hThread);
                Sleep(1500);
                SuspendThread(pi.hThread);
                check_changes(pi.hProcess, g_image_base);

                dump_all(pi.hProcess, g_image_base, target_exe);
                dump_done = 1;
                capture_dropped_files(target_dir);
                capture_dropped_files(".");

                printf("[*] Terminating process (was suspended, no damage done).\n");
                TerminateProcess(pi.hProcess, 0);
            }

            if (!alive && !dump_done) {
                printf("[!] Process exited (code %u) at %.1fs\n", ec,
                       (float)(ticks * POLL_INTERVAL_MS) / 1000.0f);
                dump_all(pi.hProcess, g_image_base, target_exe);
                capture_dropped_files(target_dir);
                capture_dropped_files(".");
                dump_done = 1;
            }

            if (ticks % 200 == 0 && !dump_done)
                printf("    ... monitoring (%.0fs)\n",
                       (float)(ticks * POLL_INTERVAL_MS) / 1000.0f);
        }

        if (!dump_done) {
            printf("[!] Timeout (%ds). Dumping current state...\n", MAX_MONITOR_SEC);
            dump_all(pi.hProcess, g_image_base, target_exe);
            capture_dropped_files(target_dir);
            TerminateProcess(pi.hProcess, 0);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    int zip_ok = create_password_zip(g_output_dir);

    printf("\n=======================================================\n");
    printf("  DONE!\n");
    printf("  Dump folder : %s\n", g_output_dir);
    if (zip_ok) {
        printf("  Archive     : %s\n", g_zip_path);
        printf("  Password    : virus\n");
        printf("  To extract  : rename .dat -> .zip\n");
    }
    printf("=======================================================\n");
    printf("\nPress Enter to exit...");
    getchar();
    return 0;
}
