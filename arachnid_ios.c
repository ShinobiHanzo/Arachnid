#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <time.h>
#include <ctype.h>
#include <dlfcn.h>

#define LOG(fmt, ...) fprintf(stderr, "[Arachnid] " fmt "\n", ##__VA_ARGS__)

typedef struct {
    void *base;
    mach_vm_size_t size;
    vm_prot_t protection;
    vm_prot_t max_protection;
    pid_t pid;
} MemSector;

MemSector *get_memory_sectors(int *num, pid_t target_pid) {
    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &task);
    if (kr != KERN_SUCCESS) {
        LOG("task_for_pid failed for PID %d: %d", target_pid, kr);
        fprintf(stderr, "Warning: Cannot access PID %d memory map. iOS restricts cross-process access.\n", target_pid);
        exit(1);
    }

    mach_vm_address_t address = 0;
    MemSector *sectors = NULL;
    int capacity = 0;
    int count = 0;

    while (1) {
        mach_vm_size_t size;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name;

        kr = mach_vm_region(task, &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_count, &object_name);
        if (kr != KERN_SUCCESS) {
            break;
        }

        if (count >= capacity) {
            capacity += 10;
            sectors = (MemSector *)realloc(sectors, capacity * sizeof(MemSector));
            if (!sectors) {
                LOG("realloc failed");
                mach_port_deallocate(mach_task_self(), task);
                exit(1);
            }
        }

        sectors[count].base = (void *)address;
        sectors[count].size = size;
        sectors[count].protection = info.protection;
        sectors[count].max_protection = info.max_protection;
        sectors[count].pid = target_pid;
        count++;

        address += size;
    }

    *num = count;
    LOG("Found %d memory sectors for PID %d", count, target_pid);
    mach_port_deallocate(mach_task_self(), task);
    return sectors;
}

int find_current_sector(MemSector *sectors, int num_sectors) {
    Dl_info info;
    if (dladdr((void *)find_current_sector, &info)) {
        void *module_addr = (void *)info.dli_fbase;
        for (int i = 0; i < num_sectors; i++) {
            if (module_addr >= sectors[i].base && module_addr < (void *)((char *)sectors[i].base + sectors[i].size)) {
                return i;
            }
        }
    }
    fprintf(stderr, "Warning: Could not determine module base address using dladdr\n");
    return -1;
}

void print_sector(FILE *out, MemSector *s, int index, int filter_mode, pid_t target_pid, int show_null) {
    fprintf(out, "Sector %d:\n", index);
    fprintf(out, "PID: %d\n", s->pid);
    fprintf(out, "Base: %p\n", s->base);
    fprintf(out, "Size: %llu\n", s->size);
    fprintf(out, "Protection: 0x%x (r:%c w:%c x:%c)\n", 
            s->protection,
            (s->protection & VM_PROT_READ) ? 'r' : '-',
            (s->protection & VM_PROT_WRITE) ? 'w' : '-',
            (s->protection & VM_PROT_EXECUTE) ? 'x' : '-');
    fprintf(out, "Max Protection: 0x%x\n", s->max_protection);

    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(out, "Content: Cannot access process %d (Error: %d)\n", target_pid, kr);
        return;
    }

    if (s->protection & VM_PROT_READ) {
        mach_vm_size_t dump_size = filter_mode ? s->size : (s->size < 256 ? s->size : 256);
        if (filter_mode && dump_size > 1048576) { // 1 MB limit
            dump_size = 1048576;
            fprintf(out, "Content (hex dump, truncated to 1MB of %llu bytes):\n", s->size);
        } else {
            fprintf(out, "Content (hex dump, %llu bytes):\n", dump_size);
        }
        unsigned char *p = (unsigned char *)s->base;
        mach_vm_size_t i = 0;
        mach_vm_size_t empty_count = 0;
        mach_vm_size_t last_printed = 0;

        while (i < dump_size) {
            unsigned char buffer[16];
            mach_vm_size_t bytes_to_read = (i + 16 <= dump_size) ? 16 : (dump_size - i);
            int is_empty = 1;

            // Read the next 16 bytes (or remaining bytes)
            for (mach_vm_size_t j = 0; j < bytes_to_read; j++) {
                unsigned char byte;
                mach_vm_size_t bytes_read;
                kr = mach_vm_read_overwrite(task, (mach_vm_address_t)(p + i + j), 1, (mach_vm_address_t)&byte, &bytes_read);
                if (kr == KERN_SUCCESS && bytes_read == 1) {
                    buffer[j] = byte;
                    if (byte != 0) {
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
                fprintf(out, "...(%llu)\n", empty_count);
                empty_count = 0;
            }

            // Print the current line
            if (bytes_to_read > 0) {
                fprintf(out, "%p: ", (void *)(p + i));
                for (mach_vm_size_t j = 0; j < 16; j++) {
                    if (j < bytes_to_read) {
                        fprintf(out, "%02x ", buffer[j]);
                    } else {
                        fprintf(out, "   ");
                    }
                }
                fprintf(out, "  ");
                for (mach_vm_size_t j = 0; j < 16; j++) {
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
            fprintf(out, "...(%llu)\n", empty_count);
        }
    } else if (target_pid == getpid()) {
        fprintf(out, "Content: Not readable (Protection: 0x%x)\n", s->protection);
        vm_prot_t new_prot = VM_PROT_READ;
        if (!(s->protection & VM_PROT_WRITE) && !(s->protection & VM_PROT_EXECUTE)) {
            kr = mach_vm_protect(task, (mach_vm_address_t)s->base, s->size, FALSE, new_prot);
            if (kr == KERN_SUCCESS) {
                fprintf(out, "Note: Temporarily set to readable to access content\n");
                mach_vm_size_t dump_size = filter_mode ? s->size : (s->size < 256 ? s->size : 256);
                if (filter_mode && dump_size > 1048576) { // 1 MB limit
                    dump_size = 1048576;
                    fprintf(out, "Content (hex dump, truncated to 1MB of %llu bytes):\n", s->size);
                } else {
                    fprintf(out, "Content (hex dump, %llu bytes):\n", dump_size);
                }
                unsigned char *p = (unsigned char *)s->base;
                mach_vm_size_t i = 0;
                mach_vm_size_t empty_count = 0;
                mach_vm_size_t last_printed = 0;

                while (i < dump_size) {
                    unsigned char buffer[16];
                    mach_vm_size_t bytes_to_read = (i + 16 <= dump_size) ? 16 : (dump_size - i);
                    int is_empty = 1;

                    // Read the next 16 bytes (or remaining bytes)
                    for (mach_vm_size_t j = 0; j < bytes_to_read; j++) {
                        unsigned char byte;
                        mach_vm_size_t bytes_read;
                        kr = mach_vm_read_overwrite(task, (mach_vm_address_t)(p + i + j), 1, (mach_vm_address_t)&byte, &bytes_read);
                        if (kr == KERN_SUCCESS && bytes_read == 1) {
                            buffer[j] = byte;
                            if (byte != 0) {
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
                        fprintf(out, "...(%llu)\n", empty_count);
                        empty_count = 0;
                    }

                    // Print the current line
                    if (bytes_to_read > 0) {
                        fprintf(out, "%p: ", (void *)(p + i));
                        for (mach_vm_size_t j = 0; j < 16; j++) {
                            if (j < bytes_to_read) {
                                fprintf(out, "%02x ", buffer[j]);
                            } else {
                                fprintf(out, "   ");
                            }
                        }
                        fprintf(out, "  ");
                        for (mach_vm_size_t j = 0; j < 16; j++) {
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
                    fprintf(out, "...(%llu)\n", empty_count);
                }

                mach_vm_protect(task, (mach_vm_address_t)s->base, s->size, FALSE, s->protection);
                fprintf(out, "Note: Restored original protection\n");
            } else {
                fprintf(out, "Note: Failed to make readable (Error: %d)\n", kr);
            }
        }
    } else {
        fprintf(out, "Content: Not readable (Protection: 0x%x)\n", s->protection);
    }
    mach_port_deallocate(mach_task_self(), task);
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
    pid_t target_pid = getpid();
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

    if (target_pid != getpid() && inject_file) {
        fprintf(stderr, "Error: Injection is only supported for the current process (PID %d)\n", getpid());
        return 1;
    }

    int num_sectors;
    MemSector *sectors = get_memory_sectors(&num_sectors, target_pid);

    int current_sector = (target_pid == getpid()) ? find_current_sector(sectors, num_sectors) : -1;
    if (current_sector >= 0) {
        fprintf(stderr, "Using sector %d\n", current_sector);
    } else if (target_pid == getpid()) {
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
        fprintf(out, "Number of memory sectors available for PID %d: %d\n", target_pid, num_sectors);
    } else if (inject_file && inject_sector >= 0 && inject_sector < num_sectors) {
        fprintf(out, "WARNING: Memory injection disabled due to iOS security restrictions\n");
        LOG("Injection attempt blocked for security");
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
                sleep(2);
                printf("\033[2J\033[H");
            }
        } while (is_live);
    }

    free(sectors);
    free(filters);
    if (out != stdout) {
        fclose(out);
    }
    return 0;
}