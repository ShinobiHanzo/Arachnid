#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

typedef struct {
    void *base;
    SIZE_T size;
    DWORD state;
    DWORD protect;
    DWORD type;
    DWORD pid;
} MemSector;

MemSector *get_memory_sectors(int *num, DWORD pid) {
    HANDLE process = (pid == GetCurrentProcessId()) ? GetCurrentProcess() : OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) {
        fprintf(stderr, "Error: Cannot open process %lu (Error: %lu)\n", pid, GetLastError());
        exit(1);
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    void *addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    MemSector *sectors = NULL;
    int capacity = 0;
    int count = 0;
    while (VirtualQueryEx(process, addr, &mbi, sizeof(mbi)) != 0) {
        if (count >= capacity) {
            capacity += 10;
            sectors = (MemSector *)realloc(sectors, capacity * sizeof(MemSector));
            if (!sectors) {
                perror("realloc");
                CloseHandle(process);
                exit(1);
            }
        }
        sectors[count].base = mbi.BaseAddress;
        sectors[count].size = mbi.RegionSize;
        sectors[count].state = mbi.State;
        sectors[count].protect = mbi.Protect;
        sectors[count].type = mbi.Type;
        sectors[count].pid = pid;
        count++;
        addr = (char *)mbi.BaseAddress + mbi.RegionSize;
    }
    *num = count;
    if (process != GetCurrentProcess()) {
        CloseHandle(process);
    }
    return sectors;
}

int find_current_sector(MemSector *sectors, int num_sectors) {
    HMODULE module = GetModuleHandle(NULL);
    void *module_addr = (void *)module;
    for (int i = 0; i < num_sectors; i++) {
        if (module_addr >= sectors[i].base && module_addr < (void *)((char *)sectors[i].base + sectors[i].size)) {
            return i;
        }
    }
    fprintf(stderr, "Warning: Could not determine module base address\n");
    return -1;
}

const char *get_state_string(DWORD state) {
    switch (state) {
        case MEM_COMMIT: return "MEM_COMMIT";
        case MEM_FREE: return "MEM_FREE";
        case MEM_RESERVE: return "MEM_RESERVE";
        default: return "Unknown";
    }
}

const char *get_protect_string(DWORD protect) {
    switch (protect) {
        case PAGE_NOACCESS: return "PAGE_NOACCESS";
        case PAGE_READONLY: return "PAGE_READONLY";
        case PAGE_READWRITE: return "PAGE_READWRITE";
        case PAGE_WRITECOPY: return "PAGE_WRITECOPY";
        case PAGE_EXECUTE: return "PAGE_EXECUTE";
        case PAGE_EXECUTE_READ: return "PAGE_EXECUTE_READ";
        case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE";
        case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
        case PAGE_GUARD: return "PAGE_GUARD";
        default: return "Other";
    }
}

const char *get_type_string(DWORD type) {
    switch (type) {
        case MEM_IMAGE: return "MEM_IMAGE";
        case MEM_MAPPED: return "MEM_MAPPED";
        case MEM_PRIVATE: return "MEM_PRIVATE";
        default: return "Unknown";
    }
}

BOOL is_admin() {
    BOOL is_admin = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
        PSID admin_group = NULL;
        if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                     DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
            if (!CheckTokenMembership(NULL, admin_group, &is_admin)) {
                is_admin = FALSE;
            }
            FreeSid(admin_group);
        }
        CloseHandle(token);
    }
    return is_admin;
}

void print_sector(FILE *out, MemSector *s, int index, int filter_mode, DWORD target_pid, int show_null) {
    fprintf(out, "Sector %d:\n", index);
    fprintf(out, "PID: %lu\n", s->pid);
    fprintf(out, "Base: %p\n", s->base);
    fprintf(out, "Size: %zu\n", s->size);
    fprintf(out, "State: %s (0x%lx)\n", get_state_string(s->state), s->state);
    fprintf(out, "Protect: %s (0x%lx)\n", get_protect_string(s->protect), s->protect);
    fprintf(out, "Type: %s (0x%lx)\n", get_type_string(s->type), s->type);

    if (s->state == MEM_COMMIT) {
        HANDLE process = (target_pid == GetCurrentProcessId()) ? GetCurrentProcess() : OpenProcess(PROCESS_VM_READ, FALSE, target_pid);
        if (!process) {
            fprintf(out, "Content: Cannot access process %lu (Error: %lu)\n", target_pid, GetLastError());
            return;
        }

        DWORD old_protect;
        BOOL can_read = (s->protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
        BOOL made_readable = FALSE;

        if (!can_read && !(s->protect & PAGE_NOACCESS) && !(s->protect & PAGE_GUARD) && target_pid == GetCurrentProcessId()) {
            if (VirtualProtect(s->base, s->size, PAGE_READONLY, &old_protect)) {
                can_read = TRUE;
                made_readable = TRUE;
                fprintf(out, "Note: Temporarily set to PAGE_READONLY to access content\n");
            } else {
                fprintf(out, "Note: Failed to make readable (Error: %lu)\n", GetLastError());
            }
        }

        if (can_read) {
            SIZE_T dump_size = filter_mode ? s->size : (s->size < 256 ? s->size : 256);
            if (filter_mode && dump_size > 1048576) { // 1 MB limit
                dump_size = 1048576;
                fprintf(out, "Content (hex dump, truncated to 1MB of %zu bytes):\n", s->size);
            } else {
                fprintf(out, "Content (hex dump, %zu bytes):\n", dump_size);
            }
            unsigned char *p = (unsigned char *)s->base;
            SIZE_T i = 0;
            SIZE_T empty_count = 0;
            SIZE_T last_printed = 0;

            while (i < dump_size) {
                unsigned char buffer[16];
                SIZE_T bytes_to_read = (i + 16 <= dump_size) ? 16 : (dump_size - i);
                int is_empty = 1;

                // Read the next 16 bytes (or remaining bytes)
                for (SIZE_T j = 0; j < bytes_to_read; j++) {
                    SIZE_T bytes_read;
                    if (ReadProcessMemory(process, p + i + j, &buffer[j], 1, &bytes_read) && bytes_read == 1) {
                        if (buffer[j] != 0) {
                            is_empty = 0;
                        }
                    } else {
                        buffer[j] = 0; // Treat unreadable bytes as zero for emptiness check
                    }
                }

                if (filter_mode && !show_null && is_empty && bytes_to_read == 16) {
                    // Accumulate empty lines in filter mode if show_null is false
                    empty_count++;
                    i += 16;
                    continue;
                }

                // Print accumulated empty lines if any
                if (empty_count > 0) {
                    fprintf(out, "...(%zu)\n", empty_count);
                    empty_count = 0;
                }

                // Print the current line
                if (bytes_to_read > 0) {
                    fprintf(out, "%p: ", (void *)(p + i));
                    for (SIZE_T j = 0; j < 16; j++) {
                        if (j < bytes_to_read) {
                            fprintf(out, "%02x ", buffer[j]);
                        } else {
                            fprintf(out, "   ");
                        }
                    }
                    fprintf(out, "  ");
                    for (SIZE_T j = 0; j < 16; j++) {
                        if (j < bytes_to_read) {
                            fprintf(out, "%c", isprint(buffer[j]) ? buffer[j] : '.');
                        } else {
                            fprintf(out, " ");
                        }
                    }
                    fprintf(out, "\n");
                    last_printed = i + bytes_to_read;
                }
                i += 16;
            }

            // Print any trailing empty lines
            if (empty_count > 0 && last_printed < dump_size) {
                fprintf(out, "...(%zu)\n", empty_count);
            }
        } else {
            fprintf(out, "Content: Not readable (Protection: %s)\n", get_protect_string(s->protect));
        }

        if (made_readable) {
            VirtualProtect(s->base, s->size, old_protect, &old_protect);
            fprintf(out, "Note: Restored original protection\n");
        }

        if (process != GetCurrentProcess()) {
            CloseHandle(process);
        }
    } else {
        fprintf(out, "Content: Not accessible (State: %s)\n", get_state_string(s->state));
    }
    fprintf(out, "\n");
}

int *parse_filters(const char *filter_str, int *filter_count) {
    int *filters = NULL;
    int capacity = 0;
    int count = 0;
    char *temp = strdup(filter_str);
    char *token = strtok(temp, ",");

    while (token) {
        int index = atoi(token);
        if (index >= 0) {
            if (count >= capacity) {
                capacity += 5;
                filters = (int *)realloc(filters, capacity * sizeof(int));
                if (!filters) {
                    perror("realloc filters");
                    free(temp);
                    exit(1);
                }
            }
            filters[count++] = index;
        }
        token = strtok(NULL, ",");
    }

    free(temp);
    *filter_count = count;
    return filters;
}

int main(int argc, char *argv[]) {
    int list_sectors = 0;
    char *output_file = NULL;
    char *inject_file = NULL;
    char *filter_str = NULL;
    int *filters = NULL;
    int filter_count = 0;
    int inject_sector = -1;
    DWORD target_pid = GetCurrentProcessId();
    int show_null = 0; // Default to false

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--list-sectors") == 0) {
            list_sectors = 1;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--filter") == 0) {
            if (++i < argc) {
                filter_str = argv[i];
            }
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (++i < argc) {
                output_file = argv[i];
            }
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--inject") == 0) {
            if (++i < argc) {
                inject_file = argv[i];
            }
            if (++i < argc) {
                inject_sector = atoi(argv[i]);
            }
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--process") == 0) {
            if (++i < argc) {
                target_pid = atoi(argv[i]);
            }
        } else if (strncmp(argv[i], "--show-null=", 12) == 0) {
            if (strcmp(argv[i] + 12, "true") == 0) {
                show_null = 1;
            } else if (strcmp(argv[i] + 12, "false") == 0) {
                show_null = 0;
            } else {
                fprintf(stderr, "Error: Invalid value for --show-null, expected 'true' or 'false'\n");
                return 1;
            }
        }
    }

    if (!is_admin()) {
        fprintf(stderr, "Warning: Not running as admin. Some memory regions may be inaccessible.\n");
    }

    if (target_pid != GetCurrentProcessId() && inject_file) {
        fprintf(stderr, "Error: Injection is only supported for the current process (PID %lu)\n", GetCurrentProcessId());
        return 1;
    }

    int num_sectors;
    MemSector *sectors = get_memory_sectors(&num_sectors, target_pid);

    int current_sector = (target_pid == GetCurrentProcessId()) ? find_current_sector(sectors, num_sectors) : -1;
    if (current_sector >= 0) {
        fprintf(stderr, "Using sector %d\n", current_sector);
    } else if (target_pid == GetCurrentProcessId()) {
        fprintf(stderr, "Warning: Could not determine current sector\n");
    }

    if (filter_str) {
        filters = parse_filters(filter_str, &filter_count);
    }

    FILE *out = stdout;
    if (output_file) {
        out = fopen(output_file, "a");
        if (!out) {
            perror("fopen");
            free(sectors);
            free(filters);
            return 1;
        }
    }

    if (list_sectors) {
        fprintf(out, "Number of memory sectors available for PID %lu: %d\n", target_pid, num_sectors);
    } else if (inject_file && inject_sector >= 0 && inject_sector < num_sectors) {
        FILE *f = fopen(inject_file, "rb");
        if (!f) {
            fprintf(out, "Error: Cannot open inject file '%s'\n", inject_file);
            goto cleanup;
        }
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *content = (char *)malloc(fsize);
        if (!content) {
            fprintf(out, "Error: Memory allocation failed\n");
            fclose(f);
            goto cleanup;
        }
        fread(content, 1, fsize, f);
        fclose(f);

        MemSector *s = &sectors[inject_sector];
        if (fsize > (long)s->size) {
            fprintf(out, "Error: File too large for sector (%ld > %zu)\n", fsize, s->size);
            free(content);
            goto cleanup;
        }

        DWORD old_protect;
        if (!VirtualProtect(s->base, s->size, PAGE_READWRITE, &old_protect)) {
            fprintf(out, "Error: VirtualProtect failed to make writable (Error: %lu)\n", GetLastError());
            free(content);
            goto cleanup;
        }

        memcpy(s->base, content, fsize);

        VirtualProtect(s->base, s->size, old_protect, &old_protect);

        free(content);
        fprintf(out, "Successfully injected content into sector %d\n", inject_sector);
    } else {
        int is_live = (out == stdout);
        do {
            free(sectors);
            sectors = get_memory_sectors(&num_sectors, target_pid);

            time_t now = time(NULL);
            char *timestamp = ctime(&now);
            fprintf(out, "%s\n", timestamp);

            if (filter_count > 0) {
                for (int i = 0; i < filter_count; i++) {
                    if (filters[i] < num_sectors) {
                        print_sector(out, &sectors[filters[i]], filters[i], 1, target_pid, show_null);
                    } else {
                        fprintf(out, "Warning: Filter index %d out of range (max: %d)\n", filters[i], num_sectors - 1);
                    }
                }
            } else {
                for (int j = 0; j < num_sectors; j++) {
                    print_sector(out, &sectors[j], j, 0, target_pid, show_null);
                }
            }

            if (is_live) {
                Sleep(1000);
                system("cls");
            }
        } while (is_live);
    }

cleanup:
    free(sectors);
    free(filters);
    if (out != stdout) {
        fclose(out);
    }
    return 0;
}