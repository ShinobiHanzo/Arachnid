#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <time.h>
#include <ctype.h>
#include <android/log.h>
#include <dlfcn.h>
#include <errno.h>

#define LOG_TAG "Arachnid"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

typedef struct {
    void *base;
    size_t size;
    char perms[5];
    char *pathname;
    pid_t pid;
} MemSector;

MemSector *get_memory_sectors(int *num, pid_t target_pid) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", target_pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        LOGE("Failed to open %s: %s", maps_path, strerror(errno));
        fprintf(stderr, "Warning: Cannot access PID %d memory map. Android restricts cross-process access.\n", target_pid);
        exit(1);
    }

    MemSector *sectors = NULL;
    int capacity = 0;
    int count = 0;
    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5], dev[10], offset[20], inode[20], pathname[256] = "";
        
        if (sscanf(line, "%lx-%lx %4s %s %s %s %255[^\n]", 
                   &start, &end, perms, offset, dev, inode, pathname) >= 6) {
            if (count >= capacity) {
                capacity += 10;
                sectors = (MemSector *)realloc(sectors, capacity * sizeof(MemSector));
                if (!sectors) {
                    LOGE("realloc failed: %s", strerror(errno));
                    fclose(maps);
                    exit(1);
                }
            }

            sectors[count].base = (void *)start;
            sectors[count].size = end - start;
            strncpy(sectors[count].perms, perms, 5);
            sectors[count].pathname = strdup(pathname[0] ? pathname : "[anonymous]");
            sectors[count].pid = target_pid;
            count++;
        }
    }

    fclose(maps);
    *num = count;
    LOGI("Found %d memory sectors for PID %d", count, target_pid);
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
    LOGE("Could not determine module base address using dladdr");
    fprintf(stderr, "Warning: Could not determine module base address using dladdr\n");
    return -1;
}

void free_sectors(MemSector *sectors, int num) {
    for (int i = 0; i < num; i++) {
        free(sectors[i].pathname);
    }
    free(sectors);
}

void print_sector(FILE *out, MemSector *s, int index, int filter_mode, pid_t target_pid, int show_null) {
    fprintf(out, "Sector %d:\n", index);
    fprintf(out, "PID: %d\n", s->pid);
    fprintf(out, "Base: %p\n", s->base);
    fprintf(out, "Size: %zu\n", s->size);
    fprintf(out, "Permissions: %s\n", s->perms);
    fprintf(out, "Pathname: %s\n", s->pathname);

    if (strchr(s->perms, 'r') && strncmp(s->pathname, "/dev/", 5) != 0) {
        size_t dump_size = filter_mode ? s->size : (s->size < 256 ? s->size : 256);
        if (filter_mode && dump_size > 1048576) { // 1 MB limit
            dump_size = 1048576;
            fprintf(out, "Content (hex dump, truncated to 1MB of %zu bytes):\n", s->size);
        } else {
            fprintf(out, "Content (hex dump, %zu bytes):\n", dump_size);
        }
        unsigned char *buffer = (unsigned char *)malloc(dump_size);
        if (!buffer) {
            fprintf(out, "Content: Memory allocation failed\n");
            LOGE("Failed to allocate buffer for sector %d", index);
            return;
        }

        struct iovec local = { .iov_base = buffer, .iov_len = dump_size };
        struct iovec remote = { .iov_base = s->base, .iov_len = dump_size };
        ssize_t bytes_read = process_vm_readv(target_pid, &local, 1, &remote, 1, 0);
        
        if (bytes_read == (ssize_t)dump_size) {
            size_t i = 0;
            size_t empty_count = 0;
            size_t last_printed = 0;

            while (i < dump_size) {
                unsigned char line_buffer[16];
                size_t bytes_to_read = (i + 16 <= dump_size) ? 16 : (dump_size - i);
                int is_empty = 1;

                // Copy the next 16 bytes (or remaining bytes)
                for (size_t j = 0; j < bytes_to_read; j++) {
                    line_buffer[j] = buffer[i + j];
                    if (line_buffer[j] != 0) {
                        is_empty = 0;
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
                    fprintf(out, "%p: ", (void *)((unsigned char *)s->base + i));
                    for (size_t j = 0; j < 16; j++) {
                        if (j < bytes_to_read) {
                            fprintf(out, "%02x ", line_buffer[j]);
                        } else {
                            fprintf(out, "   ");
                        }
                    }
                    fprintf(out, "  ");
                    for (size_t j = 0; j < 16; j++) {
                        if (j < bytes_to_read) {
                            char c = line_buffer[j];
                            fprintf(out, "%c", isprint(c) ? c : '.');
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
            fprintf(out, "Content: Failed to read memory (Error: %s)\n", strerror(errno));
            LOGE("process_vm_readv failed for sector %d: %s", index, strerror(errno));
        }
        free(buffer);
    } else {
        fprintf(out, "Content: Not readable (Permissions: %s)\n", s->perms);
        LOGE("Sector %d not readable for PID %d", index, target_pid);
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

    if (target_pid != getpid()) {
        fprintf(stderr, "Warning: Accessing another process's memory (PID %d) may be restricted on Android.\n", target_pid);
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
            LOGE("Cannot open output file: %s", output_file);
            free_sectors(sectors, num_sectors);
            free(filters);
            return 1;
        }
    }

    if (list_sectors) {
        fprintf(out, "Number of memory sectors available for PID %d: %d\n", target_pid, num_sectors);
    } else if (inject_file && inject_sector >= 0 && inject_sector < num_sectors) {
        fprintf(out, "WARNING: Memory injection disabled due to Android security restrictions\n");
        LOGE("Injection attempt blocked for security");
    } else {
        int is_live = (out == stdout);
        do {
            free_sectors(sectors, num_sectors);
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

    free_sectors(sectors, num_sectors);
    free(filters);
    if (out != stdout) {
        fclose(out);
    }
    return 0;
}