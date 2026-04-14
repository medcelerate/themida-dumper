/* themida_dumper_universal.c - Themida/WinLicense dumper (x86+x64)
 * v6.0 - Memory Harvester: dynamic region tracking, PE-sieve integration
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

/* Memory Harvester v6.0 constants */
#define MAX_DYNAMIC_REGIONS      256
#define REGION_FP_SIZE           64
#define HARVEST_SNAP_INTERVAL    10    /* every 10 ticks = 500ms */
#define HARVEST_BEHAV_INTERVAL   40    /* every 40 ticks = 2s */
#define HARVEST_REGION_THRESHOLD 3     /* trigger dump after 3+ new regions */
#define HARVEST_SETTLE_MS        3000  /* wait after trigger for packer to finish */
#define PESIEVE_TIMEOUT_MS       60000

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

/* === Memory Harvester v6.0 structures === */
typedef struct {
    ULONG_PTR base_addr;
    SIZE_T    size;
    DWORD     protect;
    BYTE      fingerprint[REGION_FP_SIZE];
    int       snapshot_first;   /* snapshot index when first seen */
    int       snapshot_last;    /* last snapshot where present */
    int       fp_changed;       /* fingerprint changed since first seen */
    int       dumped;           /* already written to disk */
} DynamicRegion;

typedef struct {
    DynamicRegion regions[MAX_DYNAMIC_REGIONS];
    int           count;
    int           index;        /* monotonically increasing snapshot number */
    DWORD         tick_ms;
} RegionSnapshot;

typedef struct {
    RegionSnapshot current;
    RegionSnapshot previous;
    /* Cumulative union of all regions ever seen (for final dump) */
    DynamicRegion  all_seen[MAX_DYNAMIC_REGIONS * 2];
    int            all_seen_count;
    /* Per-cycle deltas */
    int  new_this_cycle;
    int  disappeared;
    int  fp_changes;
    /* Behavioral trigger */
    int  behavioral_trigger;
    int  new_file_count;
    /* Timeline log */
    char timeline[64][256];     /* up to 64 timeline entries */
    int  timeline_count;
    /* PE-sieve */
    int  pesieve_ran;
    int  pesieve_exit_code;
    int  pesieve_file_count;
    char pesieve_path[MAX_PATH];
} HarvestState;

static SectionInfo  g_sections[MAX_SECTIONS];
static int          g_num_sections = 0;
static ULONG_PTR    g_image_base = 0;
static int          g_is_32bit_target = 0;
static WORD         g_pe_magic = 0;
static char         g_output_dir[MAX_PATH] = ".";
static char         g_dll_export[256] = "";
static int          g_is_dll = 0;
static int          g_is_service_dll = 0;
static int          g_no_pause = 0;
static char         g_wait_for_process[MAX_PATH] = "";
static int          g_force_direct = 0;
static int          g_force_dropper = 0;
static int          g_dropper_timeout = 60;

/* Memory Harvester globals */
static HarvestState g_harvest;
static int          g_harvest_enabled = 1;   /* on by default for dump mode */
static DWORD        g_size_of_image = 0;

/* Forward declarations for dropper mode globals used by harvest behavioral trigger */
#define MAX_WATCH_DIRS_FWD  16
static char     g_harvest_watch_dirs[MAX_WATCH_DIRS_FWD][MAX_PATH];
static int      g_harvest_watch_count = 0;

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
    return strstr(s, "http://") != NULL || strstr(s, "https://") != NULL ||
           strstr(s, "t.me/") != NULL || strstr(s, "ftp://") != NULL;
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

/* ========================================================================
 * Memory Harvester v6.0 - Dynamic executable region tracking
 * ======================================================================== */

static void harvest_init(void)
{
    memset(&g_harvest, 0, sizeof(g_harvest));

    /* Set up behavioral watch dirs (common drop locations) */
    g_harvest_watch_count = 0;
    char buf[MAX_PATH];
    if (ExpandEnvironmentStringsA("%USERPROFILE%\\Desktop", buf, MAX_PATH))
        strncpy(g_harvest_watch_dirs[g_harvest_watch_count++], buf, MAX_PATH - 1);
    if (ExpandEnvironmentStringsA("%TEMP%", buf, MAX_PATH))
        strncpy(g_harvest_watch_dirs[g_harvest_watch_count++], buf, MAX_PATH - 1);
    if (ExpandEnvironmentStringsA("%APPDATA%", buf, MAX_PATH))
        strncpy(g_harvest_watch_dirs[g_harvest_watch_count++], buf, MAX_PATH - 1);
    if (ExpandEnvironmentStringsA("%LOCALAPPDATA%", buf, MAX_PATH))
        strncpy(g_harvest_watch_dirs[g_harvest_watch_count++], buf, MAX_PATH - 1);
    if (ExpandEnvironmentStringsA("%PROGRAMDATA%", buf, MAX_PATH))
        strncpy(g_harvest_watch_dirs[g_harvest_watch_count++], buf, MAX_PATH - 1);
}

static void harvest_log(const char *fmt, ...)
{
    if (g_harvest.timeline_count >= 64) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_harvest.timeline[g_harvest.timeline_count],
              sizeof(g_harvest.timeline[0]), fmt, ap);
    va_end(ap);
    g_harvest.timeline_count++;
}

static int is_module_region(HANDLE hProc, ULONG_PTR addr)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                           GetProcessId(hProc));
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    int found = 0;

    if (Module32First(snap, &me)) {
        do {
            ULONG_PTR mod_base = (ULONG_PTR)me.modBaseAddr;
            ULONG_PTR mod_end  = mod_base + me.modBaseSize;
            if (addr >= mod_base && addr < mod_end) {
                found = 1;
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

static int take_region_snapshot(HANDLE hProc, ULONG_PTR image_base, DWORD soi)
{
    /* Swap current -> previous */
    memcpy(&g_harvest.previous, &g_harvest.current, sizeof(RegionSnapshot));
    memset(&g_harvest.current, 0, sizeof(RegionSnapshot));
    g_harvest.current.index = g_harvest.previous.index + 1;
    g_harvest.current.tick_ms = GetTickCount();

    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0x10000;
    ULONG_PTR pe_end = image_base + soi;
    int count = 0;

#ifdef _WIN64
    ULONG_PTR max_addr = g_is_32bit_target ? (ULONG_PTR)0x7FFF0000ULL
                                            : (ULONG_PTR)0x7FFFFFFFFFFFULL;
#else
    ULONG_PTR max_addr = (ULONG_PTR)0x7FFF0000;
#endif

    while (addr < max_addr && count < MAX_DYNAMIC_REGIONS) {
        if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)))
            break;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        {
            ULONG_PTR rbase = (ULONG_PTR)mbi.BaseAddress;
            SIZE_T    rsize = mbi.RegionSize;

            /* Skip regions inside the PE image - we already track those as sections */
            int inside_pe = (rbase >= image_base && rbase < pe_end);

            /* Skip known DLL modules */
            int is_mod = 0;
            if (!inside_pe) {
                is_mod = is_module_region(hProc, rbase);
            }

            if (!inside_pe && !is_mod) {
                DynamicRegion *dr = &g_harvest.current.regions[count];
                dr->base_addr = rbase;
                dr->size = rsize;
                dr->protect = mbi.Protect;
                dr->dumped = 0;
                dr->fp_changed = 0;

                /* Fingerprint first 64 bytes */
                SIZE_T nread = 0;
                ReadProcessMemory(hProc, (LPCVOID)rbase,
                                  dr->fingerprint, REGION_FP_SIZE, &nread);

                /* Check if this region was in previous snapshot */
                int was_known = 0;
                for (int i = 0; i < g_harvest.previous.count; i++) {
                    if (g_harvest.previous.regions[i].base_addr == rbase) {
                        dr->snapshot_first = g_harvest.previous.regions[i].snapshot_first;
                        was_known = 1;
                        /* Check fingerprint change */
                        if (memcmp(dr->fingerprint,
                                   g_harvest.previous.regions[i].fingerprint,
                                   REGION_FP_SIZE) != 0) {
                            dr->fp_changed = 1;
                        }
                        break;
                    }
                }
                if (!was_known) {
                    dr->snapshot_first = g_harvest.current.index;
                }
                dr->snapshot_last = g_harvest.current.index;

                /* Add to all_seen union if new */
                if (!was_known && g_harvest.all_seen_count < MAX_DYNAMIC_REGIONS * 2) {
                    memcpy(&g_harvest.all_seen[g_harvest.all_seen_count],
                           dr, sizeof(DynamicRegion));
                    g_harvest.all_seen_count++;
                }

                count++;
            }
        }

        ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    g_harvest.current.count = count;
    return count;
}

static int check_region_changes(void)
{
    int new_count = 0, disappeared = 0, fp_changes = 0;

    /* Find new regions (in current but not in previous) */
    for (int i = 0; i < g_harvest.current.count; i++) {
        DynamicRegion *cr = &g_harvest.current.regions[i];
        int found = 0;
        for (int j = 0; j < g_harvest.previous.count; j++) {
            if (g_harvest.previous.regions[j].base_addr == cr->base_addr) {
                found = 1;
                break;
            }
        }
        if (!found) {
            new_count++;
            float t = (float)(g_harvest.current.tick_ms - g_harvest.previous.tick_ms) / 1000.0f;
            printf("[!] HARVEST: NEW exec region " ADDR_FMT " (%u bytes, prot=0x%X)\n",
                   ADDR_CAST(cr->base_addr), (unsigned)cr->size, cr->protect);
            harvest_log("[T+%.1fs] Snap #%d: NEW region " ADDR_FMT " (%u bytes)",
                        (float)g_harvest.current.tick_ms / 1000.0f,
                        g_harvest.current.index,
                        ADDR_CAST(cr->base_addr), (unsigned)cr->size);
        }
        if (cr->fp_changed) {
            fp_changes++;
            harvest_log("[T+%.1fs] Snap #%d: CHANGED fp at " ADDR_FMT,
                        (float)g_harvest.current.tick_ms / 1000.0f,
                        g_harvest.current.index,
                        ADDR_CAST(cr->base_addr));
        }
    }

    /* Find disappeared regions */
    for (int j = 0; j < g_harvest.previous.count; j++) {
        int found = 0;
        for (int i = 0; i < g_harvest.current.count; i++) {
            if (g_harvest.current.regions[i].base_addr ==
                g_harvest.previous.regions[j].base_addr) {
                found = 1;
                break;
            }
        }
        if (!found) {
            disappeared++;
            harvest_log("[T+%.1fs] Snap #%d: DISAPPEARED region " ADDR_FMT,
                        (float)g_harvest.current.tick_ms / 1000.0f,
                        g_harvest.current.index,
                        ADDR_CAST(g_harvest.previous.regions[j].base_addr));
        }
    }

    g_harvest.new_this_cycle = new_count;
    g_harvest.disappeared += disappeared;
    g_harvest.fp_changes += fp_changes;
    return new_count + fp_changes;
}

static int dump_dynamic_regions(HANDLE hProc)
{
    int dumped = 0;

    /* Dump from the all_seen union - captures even ephemeral regions */
    for (int i = 0; i < g_harvest.all_seen_count; i++) {
        DynamicRegion *dr = &g_harvest.all_seen[i];
        if (dr->dumped) continue;

        char fname[MAX_PATH];
        snprintf(fname, sizeof(fname), "%s\\region_" ADDR_FMT "_%u.bin",
                 g_output_dir, ADDR_CAST(dr->base_addr), (unsigned)dr->size);

        DWORD dump_size = (DWORD)dr->size;
        if (dump_size > 64 * 1024 * 1024) dump_size = 64 * 1024 * 1024;

        BYTE *buf = (BYTE*)malloc(dump_size);
        if (!buf) continue;
        memset(buf, 0, dump_size);

        SIZE_T nread;
        DWORD chunk = 0x1000;
        int has_data = 0;
        for (DWORD off = 0; off < dump_size; off += chunk) {
            DWORD sz = (dump_size - off < chunk) ? (dump_size - off) : chunk;
            if (ReadProcessMemory(hProc, (LPCVOID)(dr->base_addr + off),
                                  buf + off, sz, &nread) && nread > 0) {
                has_data = 1;
            }
        }

        if (has_data) {
            FILE *f = fopen(fname, "wb");
            if (f) {
                fwrite(buf, 1, dump_size, f);
                fclose(f);
                printf("[+] Region dump: " ADDR_FMT " (%u bytes) -> %s\n",
                       ADDR_CAST(dr->base_addr), dump_size, fname);
                dumped++;
            }
        }

        dr->dumped = 1;
        free(buf);
    }

    /* Also try to dump current regions that might not be in all_seen yet */
    for (int i = 0; i < g_harvest.current.count; i++) {
        DynamicRegion *cr = &g_harvest.current.regions[i];
        /* Check if already dumped via all_seen */
        int already = 0;
        for (int j = 0; j < g_harvest.all_seen_count; j++) {
            if (g_harvest.all_seen[j].base_addr == cr->base_addr &&
                g_harvest.all_seen[j].dumped) {
                already = 1;
                break;
            }
        }
        if (already) continue;

        char fname[MAX_PATH];
        snprintf(fname, sizeof(fname), "%s\\region_" ADDR_FMT "_%u.bin",
                 g_output_dir, ADDR_CAST(cr->base_addr), (unsigned)cr->size);

        DWORD dump_size = (DWORD)cr->size;
        if (dump_size > 64 * 1024 * 1024) dump_size = 64 * 1024 * 1024;

        BYTE *buf = (BYTE*)malloc(dump_size);
        if (!buf) continue;
        memset(buf, 0, dump_size);

        SIZE_T nread;
        DWORD chunk = 0x1000;
        int has_data = 0;
        for (DWORD off = 0; off < dump_size; off += chunk) {
            DWORD sz = (dump_size - off < chunk) ? (dump_size - off) : chunk;
            if (ReadProcessMemory(hProc, (LPCVOID)(cr->base_addr + off),
                                  buf + off, sz, &nread) && nread > 0) {
                has_data = 1;
            }
        }

        if (has_data) {
            FILE *f = fopen(fname, "wb");
            if (f) {
                fwrite(buf, 1, dump_size, f);
                fclose(f);
                printf("[+] Region dump: " ADDR_FMT " (%u bytes) -> %s\n",
                       ADDR_CAST(cr->base_addr), dump_size, fname);
                dumped++;
            }
        }
        free(buf);
    }

    if (dumped > 0)
        printf("[+] Total dynamic regions dumped: %d\n", dumped);
    else
        printf("[*] No dynamic executable regions found outside PE image\n");

    return dumped;
}

static void detect_pesieve_path(void)
{
    if (g_harvest.pesieve_path[0] != '\0') return;

    const char *p64 = "C:\\Tools\\pe-sieve64.exe";
    const char *p32 = "C:\\Tools\\pe-sieve32.exe";
    const char *preferred = g_is_32bit_target ? p32 : p64;
    const char *fallback  = g_is_32bit_target ? p64 : p32;

    DWORD attr = GetFileAttributesA(preferred);
    if (attr != INVALID_FILE_ATTRIBUTES) {
        strncpy(g_harvest.pesieve_path, preferred, MAX_PATH - 1);
    } else {
        attr = GetFileAttributesA(fallback);
        if (attr != INVALID_FILE_ATTRIBUTES)
            strncpy(g_harvest.pesieve_path, fallback, MAX_PATH - 1);
    }

    if (g_harvest.pesieve_path[0] != '\0')
        printf("[+] PE-sieve found: %s\n", g_harvest.pesieve_path);
    else
        printf("[!] PE-sieve not found at C:\\Tools\\ (optional, skipping)\n");
}

static int run_pesieve(DWORD target_pid)
{
    if (g_harvest.pesieve_path[0] == '\0') return 0;

    char pesieve_outdir[MAX_PATH];
    snprintf(pesieve_outdir, sizeof(pesieve_outdir), "%s\\pesieve_out", g_output_dir);
    CreateDirectoryA(pesieve_outdir, NULL);

    char cmdline[MAX_PATH * 3];
    snprintf(cmdline, sizeof(cmdline),
             "\"%s\" /pid %u /dir \"%s\" /shellc /iat 3 /dmode 1 /quiet",
             g_harvest.pesieve_path, target_pid, pesieve_outdir);

    printf("\n[*] Running PE-sieve: pid=%u\n", target_pid);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                        0, NULL, NULL, &si, &pi)) {
        printf("[-] PE-sieve launch failed (error %u)\n", (unsigned)GetLastError());
        return 0;
    }

    DWORD wait = WaitForSingleObject(pi.hProcess, PESIEVE_TIMEOUT_MS);
    if (wait == WAIT_TIMEOUT) {
        printf("[!] PE-sieve timed out, terminating\n");
        TerminateProcess(pi.hProcess, 1);
    }

    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    g_harvest.pesieve_ran = 1;
    g_harvest.pesieve_exit_code = (int)ec;

    /* Count output files */
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", pesieve_outdir);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    int fc = 0;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) fc++;
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    g_harvest.pesieve_file_count = fc;
    printf("[+] PE-sieve done (exit=%u, %d files in pesieve_out)\n", (unsigned)ec, fc);
    return 1;
}

static int check_behavioral_trigger(void)
{
    int new_files = 0;
    for (int d = 0; d < g_harvest_watch_count; d++) {
        char search[MAX_PATH];
        snprintf(search, sizeof(search), "%s\\*", g_harvest_watch_dirs[d]);
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(search, &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            /* Check if file is new (created after our snapshot baseline) */
            FILETIME ft = fd.ftCreationTime;
            ULARGE_INTEGER ul;
            ul.LowPart = ft.dwLowDateTime;
            ul.HighPart = ft.dwHighDateTime;
            /* Files created in last 30 seconds are "new" */
            FILETIME now_ft;
            GetSystemTimeAsFileTime(&now_ft);
            ULARGE_INTEGER now_ul;
            now_ul.LowPart = now_ft.dwLowDateTime;
            now_ul.HighPart = now_ft.dwHighDateTime;
            if (now_ul.QuadPart - ul.QuadPart < 300000000ULL) { /* 30 sec in 100ns units */
                new_files++;
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    if (new_files > 0 && !g_harvest.behavioral_trigger) {
        g_harvest.behavioral_trigger = 1;
        g_harvest.new_file_count = new_files;
        printf("[!] HARVEST: Behavioral trigger - %d new files in watched dirs\n", new_files);
        harvest_log("[T+%.1fs] BEHAVIORAL: %d new files detected",
                    (float)GetTickCount() / 1000.0f, new_files);
    }
    return new_files;
}

static void write_harvest_report(DWORD total_elapsed_ms)
{
    char rpath[MAX_PATH];
    snprintf(rpath, sizeof(rpath), "%s\\harvest_report.txt", g_output_dir);

    FILE *f = fopen(rpath, "w");
    if (!f) return;

    fprintf(f, "=== Clarity Memory Harvester v6.0 Report ===\n");
    fprintf(f, "Target architecture: %s\n", g_is_32bit_target ? "x86" : "x64");
    fprintf(f, "Image base: " ADDR_FMT "\n", ADDR_CAST(g_image_base));
    fprintf(f, "Size of image: 0x%08X\n", g_size_of_image);
    fprintf(f, "Total analysis time: %.1f seconds\n", (float)total_elapsed_ms / 1000.0f);
    fprintf(f, "Harvest mode: %s\n\n", g_harvest_enabled ? "enabled" : "disabled");

    fprintf(f, "=== Region Timeline ===\n");
    for (int i = 0; i < g_harvest.timeline_count; i++)
        fprintf(f, "%s\n", g_harvest.timeline[i]);
    if (g_harvest.timeline_count == 0)
        fprintf(f, "(no events recorded)\n");

    fprintf(f, "\n=== Dynamic Region Summary ===\n");
    fprintf(f, "Total unique regions tracked: %d\n", g_harvest.all_seen_count);
    fprintf(f, "Regions at final snapshot: %d\n", g_harvest.current.count);
    fprintf(f, "Disappeared regions: %d\n", g_harvest.disappeared);
    fprintf(f, "Fingerprint changes observed: %d\n", g_harvest.fp_changes);
    fprintf(f, "Behavioral trigger: %s (%d new files)\n",
            g_harvest.behavioral_trigger ? "yes" : "no", g_harvest.new_file_count);

    fprintf(f, "\n=== PE-sieve Results ===\n");
    if (g_harvest.pesieve_ran) {
        fprintf(f, "PE-sieve path: %s\n", g_harvest.pesieve_path);
        fprintf(f, "Exit code: %d\n", g_harvest.pesieve_exit_code);
        fprintf(f, "Output files: %d\n", g_harvest.pesieve_file_count);
    } else {
        fprintf(f, "PE-sieve: not executed\n");
    }

    fprintf(f, "\n=== Section Status ===\n");
    for (int i = 0; i < g_num_sections; i++) {
        SectionInfo *si = &g_sections[i];
        fprintf(f, "%-12s RVA=0x%08X  changed=%s\n",
                si->name, si->rva, si->changed ? "yes" : "no");
    }

    if (g_harvest.all_seen_count == 0 && !g_harvest.pesieve_ran) {
        fprintf(f, "\n=== Note ===\n");
        fprintf(f, "No dynamic executable regions found outside PE image.\n");
        fprintf(f, "If section fingerprints also didn't change, the sample may use\n");
        fprintf(f, "Themida 3.x code virtualization (VM bytecode, not decryptable).\n");
    }

    fclose(f);
    printf("[+] Harvest report: %s\n", rpath);
}

/* End of Memory Harvester v6.0 functions */

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
            /* Skip PE executables — ransom notes are text files, not .exe/.dll */
            const char *ext = strrchr(name, '.');
            if (ext && (_stricmp(ext, ".exe") == 0 || _stricmp(ext, ".dll") == 0 ||
                        _stricmp(ext, ".scr") == 0 || _stricmp(ext, ".com") == 0)) {
                printf("    Skipped PE: %s (not a ransom note)\n", name);
                continue;
            }

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
    g_size_of_image = soi;
    dump_full_image(hProc, base, soi, target_name);

    scan_process_strings(hProc, base);

    /* Memory Harvester: dump dynamic executable regions */
    if (g_harvest_enabled) {
        printf("\n[*] Memory Harvester: dumping dynamic executable regions...\n");
        dump_dynamic_regions(hProc);
    }
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

/* ========================================================================
 * DROPPER MODE: Smart payload targeting (v5.0)
 * Detects if target is packed; if not, watches filesystem + processes
 * for the real packed payload dropped/spawned by the dropper.
 * ======================================================================== */

#define MAX_WATCH_DIRS      16
#define MAX_SNAPSHOT_FILES   1024
#define MAX_NEW_FILES        64
#define MAX_BASELINE_PIDS    1024
#define MAX_NEW_PIDS         64
#define DROPPER_POLL_MS      500

typedef struct {
    int is_packed;
    int themida_sections;
    int minimal_imports;
    int has_overlay;
    char details[256];
} PackerCheckResult;

typedef struct {
    char path[MAX_PATH];
    DWORD size_low;
} FSEntry;

typedef struct {
    HANDLE  hProcess;
    HANDLE  hThread;
    DWORD   pid;
    ULONG_PTR image_base;
    char    image_path[MAX_PATH];
} TargetInfo;

static FSEntry  g_fs_snapshot[MAX_SNAPSHOT_FILES];
static int      g_fs_count = 0;
static char     g_watch_dirs[MAX_WATCH_DIRS][MAX_PATH];
static int      g_watch_dir_count = 0;
static DWORD    g_baseline_pids[MAX_BASELINE_PIDS];
static int      g_baseline_pid_count = 0;

/* --- Packer signature check (disk file) --- */
static int check_file_for_packer(const char *filepath, PackerCheckResult *result)
{
    memset(result, 0, sizeof(*result));

    FILE *f = fopen(filepath, "rb");
    if (!f) {
        snprintf(result->details, sizeof(result->details), "Cannot open file");
        return 0;
    }

    BYTE hdr[4096];
    size_t nread = fread(hdr, 1, sizeof(hdr), f);

    /* Get file size for overlay check */
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fclose(f);

    if (nread < 256 || hdr[0] != 'M' || hdr[1] != 'Z') {
        snprintf(result->details, sizeof(result->details), "Not a PE file");
        return 0;
    }

    DWORD pe_off = *(DWORD*)(hdr + 0x3C);
    if (pe_off + 256 > nread) {
        snprintf(result->details, sizeof(result->details), "PE header beyond read range");
        return 0;
    }

    BYTE *pe = hdr + pe_off;
    if (*(DWORD*)pe != 0x00004550) {
        snprintf(result->details, sizeof(result->details), "Invalid PE signature");
        return 0;
    }

    WORD num_secs = *(WORD*)(pe + 6);
    WORD opt_size = *(WORD*)(pe + 20);
    BYTE *sec_tbl = pe + 24 + opt_size;

    /* Check section names for Themida markers */
    DWORD last_section_end = 0;
    for (int i = 0; i < num_secs && i < 32; i++) {
        BYTE *s = sec_tbl + i * 40;
        if ((BYTE*)(s + 40) > hdr + nread) break;

        char name[9];
        memcpy(name, s, 8);
        name[8] = '\0';

        DWORD raw_off = *(DWORD*)(s + 20);
        DWORD raw_sz  = *(DWORD*)(s + 16);
        if (raw_off + raw_sz > last_section_end)
            last_section_end = raw_off + raw_sz;

        if (strstr(name, ".themida") || strstr(name, ".Themida") ||
            strstr(name, "_THEMES_") || strstr(name, "Themida")) {
            result->themida_sections++;
        }
    }

    /* Overlay check */
    if (file_size > 0 && last_section_end > 0 && (long)last_section_end < file_size) {
        long overlay_size = file_size - last_section_end;
        if (overlay_size > 4096) {
            result->has_overlay = 1;
        }
    }

    /* Import count check (minimal imports = likely packed) */
    WORD magic = *(WORD*)(pe + 24);
    DWORD import_rva = 0;
    if (magic == PE32_MAGIC && pe_off + 24 + 104 < nread) {
        import_rva = *(DWORD*)(pe + 24 + 104);
    } else if (magic == PE32PLUS_MAGIC && pe_off + 24 + 120 < nread) {
        import_rva = *(DWORD*)(pe + 24 + 120);
    }
    /* We can't fully walk imports from just the header, but if import_rva == 0, no imports */
    if (import_rva == 0) result->minimal_imports = 1;

    /* Decision */
    if (result->themida_sections > 0) {
        result->is_packed = 1;
        snprintf(result->details, sizeof(result->details),
                 "Themida detected: %d Themida section(s), overlay=%s",
                 result->themida_sections, result->has_overlay ? "yes" : "no");
    } else if (result->has_overlay && result->minimal_imports) {
        result->is_packed = 1;
        snprintf(result->details, sizeof(result->details),
                 "Likely packed: overlay present + minimal imports");
    } else {
        snprintf(result->details, sizeof(result->details),
                 "Not packed (no Themida markers found)");
    }

    return result->is_packed;
}

/* --- Filesystem snapshot --- */
static void build_watch_dirs(const char *target_path)
{
    g_watch_dir_count = 0;
    char buf[MAX_PATH];

    /* Parent dir of target */
    char parent[MAX_PATH];
    strncpy(parent, target_path, MAX_PATH - 1);
    parent[MAX_PATH - 1] = '\0';
    char *last = strrchr(parent, '\\');
    if (!last) last = strrchr(parent, '/');
    if (last) *last = '\0';
    strncpy(g_watch_dirs[g_watch_dir_count++], parent, MAX_PATH);

    /* Desktop */
    if (ExpandEnvironmentStringsA("%USERPROFILE%\\Desktop", buf, MAX_PATH))
        strncpy(g_watch_dirs[g_watch_dir_count++], buf, MAX_PATH);

    /* TEMP */
    if (ExpandEnvironmentStringsA("%TEMP%", buf, MAX_PATH))
        strncpy(g_watch_dirs[g_watch_dir_count++], buf, MAX_PATH);

    /* APPDATA */
    if (ExpandEnvironmentStringsA("%APPDATA%", buf, MAX_PATH))
        strncpy(g_watch_dirs[g_watch_dir_count++], buf, MAX_PATH);

    /* LOCALAPPDATA */
    if (ExpandEnvironmentStringsA("%LOCALAPPDATA%", buf, MAX_PATH))
        strncpy(g_watch_dirs[g_watch_dir_count++], buf, MAX_PATH);

    /* PROGRAMDATA */
    if (ExpandEnvironmentStringsA("%PROGRAMDATA%", buf, MAX_PATH))
        strncpy(g_watch_dirs[g_watch_dir_count++], buf, MAX_PATH);

    printf("[*] Watching %d directories for new PE files\n", g_watch_dir_count);
}

static int is_pe_extension(const char *name)
{
    const char *ext = strrchr(name, '.');
    if (!ext) return 0;
    return (_stricmp(ext, ".exe") == 0 || _stricmp(ext, ".dll") == 0 ||
            _stricmp(ext, ".scr") == 0 || _stricmp(ext, ".com") == 0 ||
            _stricmp(ext, ".cpl") == 0);
}

static void scan_dir_for_pes(const char *dir)
{
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Track new subdirs for later scanning */
            continue;
        }
        if (!is_pe_extension(fd.cFileName)) continue;
        if (g_fs_count >= MAX_SNAPSHOT_FILES) break;

        FSEntry *e = &g_fs_snapshot[g_fs_count];
        snprintf(e->path, MAX_PATH, "%s\\%s", dir, fd.cFileName);
        e->size_low = fd.nFileSizeLow;
        g_fs_count++;
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
}

static void take_fs_snapshot(void)
{
    g_fs_count = 0;
    for (int i = 0; i < g_watch_dir_count; i++)
        scan_dir_for_pes(g_watch_dirs[i]);
    printf("[*] Filesystem snapshot: %d PE files in baseline\n", g_fs_count);
}

static int find_new_pe_files(char new_files[][MAX_PATH], int max_results)
{
    int found = 0;
    for (int d = 0; d < g_watch_dir_count && found < max_results; d++) {
        char search[MAX_PATH];
        snprintf(search, sizeof(search), "%s\\*", g_watch_dirs[d]);
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(search, &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;

        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (!is_pe_extension(fd.cFileName)) continue;

            char fullpath[MAX_PATH];
            snprintf(fullpath, sizeof(fullpath), "%s\\%s", g_watch_dirs[d], fd.cFileName);

            /* Check if in baseline */
            int in_baseline = 0;
            for (int j = 0; j < g_fs_count; j++) {
                if (_stricmp(g_fs_snapshot[j].path, fullpath) == 0) {
                    in_baseline = 1;
                    break;
                }
            }
            if (!in_baseline && found < max_results) {
                strncpy(new_files[found], fullpath, MAX_PATH);
                found++;
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);

        /* Also scan new subdirs (one level) */
        snprintf(search, sizeof(search), "%s\\*", g_watch_dirs[d]);
        hFind = FindFirstFileA(search, &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (fd.cFileName[0] == '.') continue;

            char subdir[MAX_PATH];
            snprintf(subdir, sizeof(subdir), "%s\\%s", g_watch_dirs[d], fd.cFileName);

            char sub_search[MAX_PATH];
            snprintf(sub_search, sizeof(sub_search), "%s\\*", subdir);
            WIN32_FIND_DATAA fd2;
            HANDLE hFind2 = FindFirstFileA(sub_search, &fd2);
            if (hFind2 == INVALID_HANDLE_VALUE) continue;
            do {
                if (fd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                if (!is_pe_extension(fd2.cFileName)) continue;
                char fullpath2[MAX_PATH];
                snprintf(fullpath2, sizeof(fullpath2), "%s\\%s", subdir, fd2.cFileName);
                int in_bl = 0;
                for (int j = 0; j < g_fs_count; j++) {
                    if (_stricmp(g_fs_snapshot[j].path, fullpath2) == 0) { in_bl = 1; break; }
                }
                if (!in_bl && found < max_results) {
                    strncpy(new_files[found], fullpath2, MAX_PATH);
                    found++;
                }
            } while (FindNextFileA(hFind2, &fd2));
            FindClose(hFind2);
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    return found;
}

/* --- Process enumeration --- */
static void take_process_snapshot(void)
{
    g_baseline_pid_count = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (g_baseline_pid_count < MAX_BASELINE_PIDS)
                g_baseline_pids[g_baseline_pid_count++] = pe.th32ProcessID;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

static int find_new_processes(DWORD new_pids[], int max_results)
{
    int found = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID < 8) continue;
            int in_baseline = 0;
            for (int i = 0; i < g_baseline_pid_count; i++) {
                if (g_baseline_pids[i] == pe.th32ProcessID) { in_baseline = 1; break; }
            }
            if (!in_baseline && found < max_results) {
                new_pids[found++] = pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static int get_process_image_path(DWORD pid, char *path, int path_size)
{
    path[0] = '\0';
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return 0;

    /* Try QueryFullProcessImageNameA (Vista+) */
    typedef BOOL (WINAPI *pfnQueryFullProcessImageNameA)(HANDLE, DWORD, LPSTR, PDWORD);
    static pfnQueryFullProcessImageNameA pQuery = NULL;
    static int resolved = 0;
    if (!resolved) {
        HMODULE hK32 = GetModuleHandleA("kernel32.dll");
        if (hK32) pQuery = (pfnQueryFullProcessImageNameA)
            GetProcAddress(hK32, "QueryFullProcessImageNameA");
        resolved = 1;
    }

    if (pQuery) {
        DWORD sz = (DWORD)path_size;
        if (pQuery(hProc, 0, path, &sz)) {
            CloseHandle(hProc);
            return 1;
        }
    }

    /* Fallback: module snapshot */
    CloseHandle(hProc);
    HANDLE modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (modSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me;
        me.dwSize = sizeof(me);
        if (Module32First(modSnap, &me)) {
            strncpy(path, me.szExePath, path_size - 1);
            path[path_size - 1] = '\0';
            CloseHandle(modSnap);
            return 1;
        }
        CloseHandle(modSnap);
    }
    return 0;
}

static HANDLE get_main_thread_handle(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return NULL;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    HANDLE hThread = NULL;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread) break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return hThread;
}

/* --- Attach and assess state --- */
static int attach_and_assess(HANDLE hProc, HANDLE hThread, ULONG_PTR image_base)
{
    /* Suspend immediately */
    SuspendThread(hThread);

    /* Fingerprint sections */
    if (!read_pe_sections(hProc, image_base)) {
        printf("[-] Cannot read PE sections from attached process\n");
        ResumeThread(hThread);
        return -1;
    }

    /* Check: are sections already decrypted? */
    int decrypted_count = 0;
    for (int i = 0; i < g_num_sections; i++) {
        SectionInfo *si = &g_sections[i];
        if (si->vsize == 0 || si->vsize < 0x1000) continue;
        int nz = 0;
        for (int j = 0; j < FINGERPRINT_SIZE; j++)
            if (si->fingerprint[j] != 0) nz++;
        if (nz > (int)(FINGERPRINT_SIZE * 0.8))
            decrypted_count++;
    }

    if (decrypted_count >= 2) {
        printf("[+] Sections already decrypted (%d sections with data). Dumping now.\n",
               decrypted_count);
        return 1;  /* dump immediately */
    } else {
        printf("[*] Sections still encrypted (%d decrypted). Resuming for monitor loop.\n",
               decrypted_count);
        ResumeThread(hThread);
        return 0;  /* enter poll loop */
    }
}

/* --- Wait for named process (--wait-for mode) --- */
static int wait_for_named_process(const char *proc_name, int timeout_sec, TargetInfo *found)
{
    int ticks = 0;
    int max_ticks = (timeout_sec * 1000) / DROPPER_POLL_MS;

    printf("[*] Polling for process '%s' (up to %ds)...\n", proc_name, timeout_sec);

    while (ticks < max_ticks) {
        Sleep(DROPPER_POLL_MS);
        ticks++;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, proc_name) == 0) {
                    CloseHandle(snap);
                    printf("[+] Found '%s' (PID %u) at %.1fs\n",
                           proc_name, pe.th32ProcessID,
                           (float)(ticks * DROPPER_POLL_MS) / 1000.0f);

                    found->pid = pe.th32ProcessID;
                    found->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
                    found->hThread = get_main_thread_handle(pe.th32ProcessID);
                    get_process_image_path(pe.th32ProcessID, found->image_path, MAX_PATH);

                    if (found->hProcess) {
                        detect_target_architecture(found->hProcess, &found->image_base);
                    }
                    return (found->hProcess != NULL) ? 1 : 0;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);

        if (ticks % 20 == 0)
            printf("    ... waiting for '%s' (%.0fs)\n", proc_name,
                   (float)(ticks * DROPPER_POLL_MS) / 1000.0f);
    }

    printf("[!] Timeout: '%s' never appeared after %ds\n", proc_name, timeout_sec);
    return 0;
}

/* --- Dropper mode (auto-discover packed payload) --- */
static int dropper_mode(const char *target_exe, int timeout_sec, TargetInfo *found)
{
    memset(found, 0, sizeof(*found));

    build_watch_dirs(target_exe);
    take_fs_snapshot();
    take_process_snapshot();

    /* Launch sample normally (NOT suspended) */
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    char cmdline[MAX_PATH * 2];
    strncpy(cmdline, target_exe, sizeof(cmdline) - 1);
    cmdline[sizeof(cmdline) - 1] = '\0';

    printf("[*] Launching dropper (normal, not suspended)...\n");
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed for dropper (error %u)\n", (unsigned)GetLastError());
        return 0;
    }
    printf("[+] Dropper PID=%u\n", pi.dwProcessId);
    CloseHandle(pi.hThread);

    int ticks = 0;
    int max_ticks = (timeout_sec * 1000) / DROPPER_POLL_MS;
    int dropper_exited = 0;
    int post_exit_ticks = 0;

    while (ticks < max_ticks) {
        Sleep(DROPPER_POLL_MS);
        ticks++;

        /* Check if dropper still alive */
        if (!dropper_exited) {
            DWORD ec;
            if (!GetExitCodeProcess(pi.hProcess, &ec) || ec != STILL_ACTIVE) {
                dropper_exited = 1;
                printf("[*] Dropper exited at %.1fs. Scanning for 10 more seconds...\n",
                       (float)(ticks * DROPPER_POLL_MS) / 1000.0f);
                int remaining = (10 * 1000) / DROPPER_POLL_MS;
                if (ticks + remaining < max_ticks)
                    max_ticks = ticks + remaining;
            }
        }

        /* Scan for new PE files on disk */
        char new_files[MAX_NEW_FILES][MAX_PATH];
        int nf = find_new_pe_files(new_files, MAX_NEW_FILES);

        for (int i = 0; i < nf; i++) {
            PackerCheckResult pr;
            if (check_file_for_packer(new_files[i], &pr)) {
                printf("[+] PACKED PE ON DISK: %s (%s)\n", new_files[i], pr.details);

                /* Find matching running process */
                DWORD new_pids[MAX_NEW_PIDS];
                int np = find_new_processes(new_pids, MAX_NEW_PIDS);
                for (int p = 0; p < np; p++) {
                    char img_path[MAX_PATH];
                    if (get_process_image_path(new_pids[p], img_path, MAX_PATH)) {
                        if (_stricmp(img_path, new_files[i]) == 0 ||
                            _stricmp(get_basename(img_path), get_basename(new_files[i])) == 0) {
                            printf("[+] MATCHED PROCESS: PID %u (%s)\n", new_pids[p], img_path);
                            found->pid = new_pids[p];
                            found->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, new_pids[p]);
                            found->hThread = get_main_thread_handle(new_pids[p]);
                            strncpy(found->image_path, img_path, MAX_PATH);
                            if (found->hProcess)
                                detect_target_architecture(found->hProcess, &found->image_base);
                            CloseHandle(pi.hProcess);
                            return (found->hProcess != NULL) ? 1 : 0;
                        }
                    }
                }
                /* Packed PE on disk but not yet running — wait a bit more */
                printf("[*] Packed PE found but not yet running. Waiting...\n");
            }
        }

        /* Also check new processes directly (file may have been deleted) */
        DWORD new_pids[MAX_NEW_PIDS];
        int np = find_new_processes(new_pids, MAX_NEW_PIDS);
        for (int p = 0; p < np; p++) {
            char img_path[MAX_PATH];
            if (!get_process_image_path(new_pids[p], img_path, MAX_PATH)) continue;

            /* Skip system processes */
            if (strstr(img_path, "\\Windows\\") && !strstr(img_path, "\\Temp\\")) continue;

            PackerCheckResult pr;
            DWORD attr = GetFileAttributesA(img_path);
            if (attr != INVALID_FILE_ATTRIBUTES) {
                if (check_file_for_packer(img_path, &pr)) {
                    printf("[+] PACKED PROCESS: PID %u (%s) - %s\n",
                           new_pids[p], img_path, pr.details);
                    found->pid = new_pids[p];
                    found->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, new_pids[p]);
                    found->hThread = get_main_thread_handle(new_pids[p]);
                    strncpy(found->image_path, img_path, MAX_PATH);
                    if (found->hProcess)
                        detect_target_architecture(found->hProcess, &found->image_base);
                    CloseHandle(pi.hProcess);
                    return (found->hProcess != NULL) ? 1 : 0;
                }
            }
        }

        if (ticks % 20 == 0)
            printf("    ... scanning (%.0fs, %d new files, %d new procs)\n",
                   (float)(ticks * DROPPER_POLL_MS) / 1000.0f, nf, np);
    }

    printf("[!] Dropper mode timeout (%ds). No packed payload found.\n", timeout_sec);
    CloseHandle(pi.hProcess);
    return 0;
}

/* --- Write dropper mode metadata --- */
static void write_dropper_info(const char *original, const char *payload, DWORD pid,
                               const char *method, float discovery_time)
{
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\dropper_mode_info.txt", g_output_dir);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "Dropper Mode Activated\n");
    fprintf(f, "Original Sample: %s\n", original);
    fprintf(f, "Packed Payload: %s\n", payload);
    fprintf(f, "Payload PID: %u\n", pid);
    fprintf(f, "Discovery Method: %s\n", method);
    fprintf(f, "Discovery Time: %.1f seconds\n", discovery_time);
    fclose(f);
    printf("[+] Wrote dropper_mode_info.txt\n");
}

/* ======================================================================== */

int main(int argc, char *argv[])
{
    printf("=======================================================\n");
    printf("  Themida Section Dumper v6.0 (Memory Harvester)\n");
    printf("  Supports 32-bit AND 64-bit PE targets\n");
    printf("  + Dynamic region tracking + PE-sieve integration\n");
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
        printf("  --wait-for=Name     Wait for a specific process to spawn, then dump it\n");
        printf("  --dropper-timeout=N Dropper mode timeout in seconds (default: 60)\n");
        printf("  --force-direct      Skip packer check, use direct monitor mode\n");
        printf("  --force-dropper     Force dropper mode even if target appears packed\n");
        printf("  --kill-vmtools      Kill VMware/VBox Tools (disables shared folders!)\n");
        printf("  --no-pause          Exit immediately after dumping (no Press Enter prompt)\n");
        printf("  --no-harvest        Disable memory harvester (section-only monitoring)\n");
        printf("  --pesieve-path=PATH Path to pe-sieve exe (default: auto-detect)\n\n");
        printf("DLL examples:\n");
        printf("  %s malware.dll\n", argv[0]);
        printf("  %s malware.dll --dll-export=ServiceMain\n", argv[0]);
        printf("  %s malware.dll --dll-export=#1\n", argv[0]);
        printf("\nPress Enter to exit...");
        if (!g_no_pause) getchar();
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
        if (!g_no_pause) getchar();
        return 1;
    }

    enable_debug_privilege();

    const char *target_exe = argv[1];
    for (int i = 2; i < argc; i++) {
        if (strncmp(argv[i], "--dll-export=", 13) == 0) {
            strncpy(g_dll_export, argv[i] + 13, sizeof(g_dll_export) - 1);
        } else if (strncmp(argv[i], "--wait-for=", 11) == 0) {
            strncpy(g_wait_for_process, argv[i] + 11, sizeof(g_wait_for_process) - 1);
        } else if (strncmp(argv[i], "--dropper-timeout=", 18) == 0) {
            g_dropper_timeout = atoi(argv[i] + 18);
            if (g_dropper_timeout < 5) g_dropper_timeout = 5;
            if (g_dropper_timeout > 300) g_dropper_timeout = 300;
        } else if (strcmp(argv[i], "--force-direct") == 0) {
            g_force_direct = 1;
        } else if (strcmp(argv[i], "--force-dropper") == 0) {
            g_force_dropper = 1;
        } else if (strcmp(argv[i], "--kill-vmtools") == 0) {
            kill_vmtools = 1;
        } else if (strcmp(argv[i], "--no-pause") == 0) {
            g_no_pause = 1;
        } else if (strcmp(argv[i], "--no-harvest") == 0) {
            g_harvest_enabled = 0;
        } else if (strncmp(argv[i], "--pesieve-path=", 15) == 0) {
            strncpy(g_harvest.pesieve_path, argv[i] + 15, MAX_PATH - 1);
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
        if (!g_no_pause) getchar();
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
        if (!g_no_pause) getchar();
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
            if (!g_no_pause) getchar();
            return 1;
        }
        g_image_base = svc_dll_base;

        if (!read_pe_sections(hProc, g_image_base)) {
            printf("[-] Cannot read PE sections\n");
            cleanup_temp_service();
            CloseHandle(hProc);
            printf("\nPress Enter to exit...");
            if (!g_no_pause) getchar();
            return 1;
        }

        printf("\n[*] Service DLL loaded. Dumping (already decrypted)...\n");
        dump_all(hProc, g_image_base, target_exe);
        capture_dropped_files(target_dir);
        capture_dropped_files(".");

        cleanup_temp_service();
        CloseHandle(hProc);

    } else {
        /* === SMART PAYLOAD TARGETING (v5.0) === */
        HANDLE hTargetProc = NULL;
        HANDLE hTargetThread = NULL;
        int skip_monitor = 0;
        int used_dropper_mode = 0;
        char dropper_payload_path[MAX_PATH] = "";
        DWORD dropper_payload_pid = 0;
        float dropper_discovery_time = 0;

        /* Priority 1: --wait-for=process.exe (targeted mode) */
        if (g_wait_for_process[0] != '\0' && !g_is_dll) {
            printf("\n[*] === TARGETED MODE: --wait-for=%s ===\n", g_wait_for_process);

            /* Launch sample normally — don't touch it after this */
            char cmdline[MAX_PATH * 2];
            strncpy(cmdline, target_exe, sizeof(cmdline) - 1);
            cmdline[sizeof(cmdline) - 1] = '\0';
            STARTUPINFOA si2;
            PROCESS_INFORMATION pi2;
            memset(&si2, 0, sizeof(si2)); si2.cb = sizeof(si2);
            memset(&pi2, 0, sizeof(pi2));
            CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si2, &pi2);
            printf("[+] Launched sample PID=%u. Now just waiting for '%s'...\n",
                   pi2.dwProcessId, g_wait_for_process);
            CloseHandle(pi2.hThread);
            CloseHandle(pi2.hProcess);

            /* Wait for the target process using the FULL analysis time.
               Don't kill anything. Don't fall back. Just wait. */
            int total_wait = MAX_MONITOR_SEC;
            TargetInfo found;
            memset(&found, 0, sizeof(found));
            DWORD t_start = GetTickCount();
            if (wait_for_named_process(g_wait_for_process, total_wait, &found)) {
                dropper_discovery_time = (float)(GetTickCount() - t_start) / 1000.0f;
                strncpy(dropper_payload_path, found.image_path, MAX_PATH);
                dropper_payload_pid = found.pid;

                PackerCheckResult pr;
                int packed = check_file_for_packer(found.image_path, &pr);
                if (packed) printf("[+] Confirmed packed: %s\n", pr.details);
                else printf("[!] WARNING: '%s' not packed. Dumping anyway.\n", g_wait_for_process);

                hTargetProc = found.hProcess;
                hTargetThread = found.hThread;
                g_image_base = found.image_base;

                int assess = attach_and_assess(hTargetProc, hTargetThread, g_image_base);
                if (assess == 1) skip_monitor = 1;
                else if (assess < 0) { hTargetProc = NULL; hTargetThread = NULL; }
                used_dropper_mode = 1;
            } else {
                printf("[!] '%s' never appeared after %ds. Nothing to dump.\n",
                       g_wait_for_process, total_wait);
                /* Don't fall back. Don't kill. Just exit cleanly. */
            }

        /* Priority 2: --force-direct (skip all smart targeting) */
        } else if (g_force_direct || g_is_dll) {
            printf("[*] Direct mode (--force-direct or DLL target)\n");

        /* Priority 3: --force-dropper */
        } else if (g_force_dropper) {
            printf("\n[*] === FORCED DROPPER MODE ===\n");
            TargetInfo found;
            memset(&found, 0, sizeof(found));
            DWORD t_start = GetTickCount();
            if (dropper_mode(target_exe, g_dropper_timeout, &found)) {
                dropper_discovery_time = (float)(GetTickCount() - t_start) / 1000.0f;
                strncpy(dropper_payload_path, found.image_path, MAX_PATH);
                dropper_payload_pid = found.pid;
                hTargetProc = found.hProcess;
                hTargetThread = found.hThread;
                g_image_base = found.image_base;
                int assess = attach_and_assess(hTargetProc, hTargetThread, g_image_base);
                if (assess == 1) skip_monitor = 1;
                else if (assess < 0) { hTargetProc = NULL; hTargetThread = NULL; }
                used_dropper_mode = 1;
            }

        /* Priority 4: Default — packer check, then dropper if not packed */
        } else {
            PackerCheckResult packer_result;
            int is_packed = check_file_for_packer(target_exe, &packer_result);
            printf("[*] Packer check: %s\n", packer_result.details);

            if (!is_packed) {
                printf("\n[*] === AUTO DROPPER MODE (target not packed) ===\n");
                TargetInfo found;
                memset(&found, 0, sizeof(found));
                DWORD t_start = GetTickCount();
                if (dropper_mode(target_exe, g_dropper_timeout, &found)) {
                    dropper_discovery_time = (float)(GetTickCount() - t_start) / 1000.0f;
                    strncpy(dropper_payload_path, found.image_path, MAX_PATH);
                    dropper_payload_pid = found.pid;
                    hTargetProc = found.hProcess;
                    hTargetThread = found.hThread;
                    g_image_base = found.image_base;
                    int assess = attach_and_assess(hTargetProc, hTargetThread, g_image_base);
                    if (assess == 1) skip_monitor = 1;
                    else if (assess < 0) { hTargetProc = NULL; hTargetThread = NULL; }
                    used_dropper_mode = 1;
                } else {
                    printf("[!] No packed payload found. Falling back to direct mode.\n");
                }
            } else {
                printf("[*] Target is packed. Using direct mode.\n");
            }
        }

        /* === DUMP PHASE === */
        if (skip_monitor && hTargetProc) {
            /* Already unpacked — dump immediately */
            printf("\n[*] Dumping already-decrypted process...\n");
            DWORD skip_pid = GetProcessId(hTargetProc);
            if (g_harvest_enabled) {
                harvest_init();
                detect_pesieve_path();
                take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
            }
            dump_all(hTargetProc, g_image_base, target_exe);
            if (g_harvest_enabled) {
                run_pesieve(skip_pid);
                write_harvest_report(0);
            }
            capture_dropped_files(target_dir);
            capture_dropped_files(".");
            TerminateProcess(hTargetProc, 0);
            CloseHandle(hTargetProc);
            if (hTargetThread) CloseHandle(hTargetThread);

        } else if (hTargetProc && hTargetThread) {
            /* Attached to packed process, still encrypted — enter monitor loop */
            printf("\n[*] Monitoring attached process for decryption...\n");
            DWORD target_pid = GetProcessId(hTargetProc);

            /* Memory Harvester: initialize and take baseline snapshot */
            if (g_harvest_enabled) {
                harvest_init();
                detect_pesieve_path();
                take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                harvest_log("[T+0.0s] Baseline: %d exec regions outside PE",
                            g_harvest.current.count);
                printf("[*] Harvest baseline: %d executable regions outside PE\n",
                       g_harvest.current.count);
            }

            int ticks = 0, max_ticks = (MAX_MONITOR_SEC * 1000) / POLL_INTERVAL_MS;
            int dump_done = 0;

            while (!dump_done && ticks < max_ticks) {
                Sleep(POLL_INTERVAL_MS);
                ticks++;

                DWORD ec;
                int alive = (GetExitCodeProcess(hTargetProc, &ec) && ec == STILL_ACTIVE);
                int changed = check_changes(hTargetProc, g_image_base);

                /* Harvest: periodic region snapshot */
                int harvest_trigger = 0;
                if (g_harvest_enabled && (ticks % HARVEST_SNAP_INTERVAL == 0) && alive) {
                    take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                    check_region_changes();
                    if (g_harvest.new_this_cycle >= HARVEST_REGION_THRESHOLD)
                        harvest_trigger = 1;
                }

                /* Harvest: periodic behavioral check */
                if (g_harvest_enabled && (ticks % HARVEST_BEHAV_INTERVAL == 0) && alive) {
                    check_behavioral_trigger();
                    if (g_harvest.behavioral_trigger && g_harvest.current.count > 0)
                        harvest_trigger = 1;
                }

                /* Trigger 1: Section fingerprint changed (existing behavior) */
                if (changed > 0) {
                    SuspendThread(hTargetThread);
                    printf("[!] Decryption detected! Process SUSPENDED.\n");
                    Sleep(500);
                    ResumeThread(hTargetThread);
                    Sleep(1500);
                    SuspendThread(hTargetThread);
                    check_changes(hTargetProc, g_image_base);
                    if (g_harvest_enabled)
                        take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);

                    dump_all(hTargetProc, g_image_base, target_exe);
                    if (g_harvest_enabled && alive) run_pesieve(target_pid);
                    dump_done = 1;
                    capture_dropped_files(target_dir);
                    capture_dropped_files(".");
                    TerminateProcess(hTargetProc, 0);
                }

                /* Trigger 2: Harvest region threshold or behavioral (NEW) */
                if (harvest_trigger && !dump_done) {
                    printf("[!] HARVEST TRIGGER: %s at %.1fs\n",
                           g_harvest.new_this_cycle >= HARVEST_REGION_THRESHOLD
                             ? "3+ new executable regions"
                             : "behavioral signal + regions",
                           (float)(ticks * POLL_INTERVAL_MS) / 1000.0f);
                    harvest_log("[T+%.1fs] DUMP TRIGGER: %s",
                                (float)(ticks * POLL_INTERVAL_MS) / 1000.0f,
                                g_harvest.new_this_cycle >= HARVEST_REGION_THRESHOLD
                                  ? "REGION_THRESHOLD" : "BEHAVIORAL");
                    Sleep(HARVEST_SETTLE_MS);
                    take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                    SuspendThread(hTargetThread);

                    dump_all(hTargetProc, g_image_base, target_exe);
                    if (alive) run_pesieve(target_pid);
                    dump_done = 1;
                    capture_dropped_files(target_dir);
                    capture_dropped_files(".");
                    TerminateProcess(hTargetProc, 0);
                }

                /* Trigger 3: Process exited */
                if (!alive && !dump_done) {
                    printf("[!] Process exited (code %u) at %.1fs\n", ec,
                           (float)(ticks * POLL_INTERVAL_MS) / 1000.0f);
                    if (g_harvest_enabled)
                        take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                    dump_all(hTargetProc, g_image_base, target_exe);
                    capture_dropped_files(target_dir);
                    capture_dropped_files(".");
                    dump_done = 1;
                }

                if (ticks % 200 == 0 && !dump_done)
                    printf("    ... monitoring (%.0fs) sections=%d regions=%d\n",
                           (float)(ticks * POLL_INTERVAL_MS) / 1000.0f,
                           changed, g_harvest_enabled ? g_harvest.current.count : 0);
            }

            if (!dump_done) {
                printf("[!] Timeout (%ds). Dumping current state...\n", MAX_MONITOR_SEC);
                if (g_harvest_enabled)
                    take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                dump_all(hTargetProc, g_image_base, target_exe);
                if (g_harvest_enabled) run_pesieve(target_pid);
                capture_dropped_files(target_dir);
                TerminateProcess(hTargetProc, 0);
            }

            /* Write harvest report */
            if (g_harvest_enabled)
                write_harvest_report(ticks * POLL_INTERVAL_MS);

            CloseHandle(hTargetProc);
            CloseHandle(hTargetThread);

        } else {
            /* === ORIGINAL DIRECT MODE (fallback) === */
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

            printf("[*] Launching as SUSPENDED (direct mode)...\n");
            if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                                CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
                DWORD err = GetLastError();
                printf("[-] CreateProcess failed (error %u)\n", (unsigned)err);
                if (err == 740)
                    printf("    Hint: Try running this tool as Administrator.\n");
                printf("\nPress Enter to exit...");
                if (!g_no_pause) getchar();
                return 1;
            }
            printf("[+] PID=%u TID=%u\n", pi.dwProcessId, pi.dwThreadId);

            if (!detect_target_architecture(pi.hProcess, &g_image_base)) {
                printf("[-] Cannot determine target architecture or image base\n");
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                printf("\nPress Enter to exit...");
                if (!g_no_pause) getchar();
                return 1;
            }

            if (!read_pe_sections(pi.hProcess, g_image_base)) {
                printf("[-] Cannot read PE sections\n");
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                printf("\nPress Enter to exit...");
                if (!g_no_pause) getchar();
                return 1;
            }

            printf("\n[*] Resuming process...\n");
            ResumeThread(pi.hThread);

            /* Memory Harvester: initialize and take baseline snapshot */
            if (g_harvest_enabled) {
                harvest_init();
                detect_pesieve_path();
                take_region_snapshot(pi.hProcess, g_image_base, g_size_of_image);
                harvest_log("[T+0.0s] Baseline: %d exec regions outside PE",
                            g_harvest.current.count);
                printf("[*] Harvest baseline: %d executable regions outside PE\n",
                       g_harvest.current.count);
            }

            int ticks = 0, max_ticks = (MAX_MONITOR_SEC * 1000) / POLL_INTERVAL_MS;
            int dump_done = 0;

            while (!dump_done && ticks < max_ticks) {
                Sleep(POLL_INTERVAL_MS);
                ticks++;

                DWORD ec;
                int alive = (GetExitCodeProcess(pi.hProcess, &ec) && ec == STILL_ACTIVE);
                int changed = check_changes(pi.hProcess, g_image_base);

                /* Harvest: periodic region snapshot */
                int harvest_trigger = 0;
                if (g_harvest_enabled && (ticks % HARVEST_SNAP_INTERVAL == 0) && alive) {
                    take_region_snapshot(pi.hProcess, g_image_base, g_size_of_image);
                    check_region_changes();
                    if (g_harvest.new_this_cycle >= HARVEST_REGION_THRESHOLD)
                        harvest_trigger = 1;
                }

                /* Harvest: periodic behavioral check */
                if (g_harvest_enabled && (ticks % HARVEST_BEHAV_INTERVAL == 0) && alive) {
                    check_behavioral_trigger();
                    if (g_harvest.behavioral_trigger && g_harvest.current.count > 0)
                        harvest_trigger = 1;
                }

                /* Trigger 1: Section fingerprint changed (existing behavior) */
                if (changed > 0) {
                    SuspendThread(pi.hThread);
                    printf("[!] Decryption detected! Process SUSPENDED.\n");
                    Sleep(500);
                    ResumeThread(pi.hThread);
                    Sleep(1500);
                    SuspendThread(pi.hThread);
                    check_changes(pi.hProcess, g_image_base);
                    if (g_harvest_enabled)
                        take_region_snapshot(pi.hProcess, g_image_base, g_size_of_image);

                    dump_all(pi.hProcess, g_image_base, target_exe);
                    if (g_harvest_enabled && alive) run_pesieve(pi.dwProcessId);
                    dump_done = 1;
                    capture_dropped_files(target_dir);
                    capture_dropped_files(".");
                    TerminateProcess(pi.hProcess, 0);
                }

                /* Trigger 2: Harvest region threshold or behavioral */
                if (harvest_trigger && !dump_done) {
                    printf("[!] HARVEST TRIGGER: %s at %.1fs\n",
                           g_harvest.new_this_cycle >= HARVEST_REGION_THRESHOLD
                             ? "3+ new executable regions"
                             : "behavioral signal + regions",
                           (float)(ticks * POLL_INTERVAL_MS) / 1000.0f);
                    harvest_log("[T+%.1fs] DUMP TRIGGER: %s",
                                (float)(ticks * POLL_INTERVAL_MS) / 1000.0f,
                                g_harvest.new_this_cycle >= HARVEST_REGION_THRESHOLD
                                  ? "REGION_THRESHOLD" : "BEHAVIORAL");
                    Sleep(HARVEST_SETTLE_MS);
                    take_region_snapshot(pi.hProcess, g_image_base, g_size_of_image);
                    SuspendThread(pi.hThread);

                    dump_all(pi.hProcess, g_image_base, target_exe);
                    if (alive) run_pesieve(pi.dwProcessId);
                    dump_done = 1;
                    capture_dropped_files(target_dir);
                    capture_dropped_files(".");
                    TerminateProcess(pi.hProcess, 0);
                }

                /* Trigger 3: Process exited */
                if (!alive && !dump_done) {
                    printf("[!] Process exited (code %u) at %.1fs\n", ec,
                           (float)(ticks * POLL_INTERVAL_MS) / 1000.0f);
                    if (g_harvest_enabled)
                        take_region_snapshot(pi.hProcess, g_image_base, g_size_of_image);
                    dump_all(pi.hProcess, g_image_base, target_exe);
                    capture_dropped_files(target_dir);
                    capture_dropped_files(".");
                    dump_done = 1;
                }

                if (ticks % 200 == 0 && !dump_done)
                    printf("    ... monitoring (%.0fs) sections=%d regions=%d\n",
                           (float)(ticks * POLL_INTERVAL_MS) / 1000.0f,
                           changed, g_harvest_enabled ? g_harvest.current.count : 0);
            }

            if (!dump_done) {
                printf("[!] Timeout (%ds). Dumping current state...\n", MAX_MONITOR_SEC);
                if (g_harvest_enabled)
                    take_region_snapshot(pi.hProcess, g_image_base, g_size_of_image);
                dump_all(pi.hProcess, g_image_base, target_exe);
                if (g_harvest_enabled) run_pesieve(pi.dwProcessId);
                capture_dropped_files(target_dir);
                TerminateProcess(pi.hProcess, 0);
            }

            /* Write harvest report */
            if (g_harvest_enabled)
                write_harvest_report(ticks * POLL_INTERVAL_MS);

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        /* Write dropper mode metadata if used */
        if (used_dropper_mode && dropper_payload_path[0] != '\0') {
            const char *method = (g_wait_for_process[0] != '\0') ?
                "wait_for_named_process" : "filesystem_scan + process_match";
            write_dropper_info(target_exe, dropper_payload_path,
                              dropper_payload_pid, method, dropper_discovery_time);
        }
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
    if (!g_no_pause) {
        printf("\nPress Enter to exit...");
        getchar();
    }
    return 0;
}
