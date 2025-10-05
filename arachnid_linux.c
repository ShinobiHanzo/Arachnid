#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <dlfcn.h>

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
        fprintf(stderr, "Error: Cannot open %s (Error: %s)\n", maps_path, strerror(errno));
        exit(1);
    }

    MemSector *sectors = NULL;
    int capacity = 0;
    int count = 0;
    char line[256];
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5], pathname[256] = "";
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &start, &end, perms, pathname) < 3) {
            continue;
        }

        if (count >= capacity) {
            capacity += 10;
            sectors = (MemSector *)realloc(sectors, capacity * sizeof(MemSector));
            if (!sectors) {
                perror("realloc");
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

    fclose(maps);
    *num = count;
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

    if (strchr(s->perms, 'r')) {
        size_t dump_size = filter_mode ? s->size : (s->size < 256 ? s->size : 256);
        if (filter_mode && dump_size > 1048576) { // 1 MB limit
            dump_size = 1048576;
            fprintf(out, "Content (hex dump, truncated to 1MB of %zu bytes):\n", s->size);
        } else {
            fprintf(out, "Content (hex dump, %zu bytes):\n", dump_size);
        }
        unsigned char *p = (unsigned char *)s->base;

        if (target_pid == getpid()) {
            size_t i = 0;
            size_t empty_count = 0;
            size_t last_printed = 0;

            while (i < dump_size) {
                unsigned char buffer[16];
                size_t bytes_to_read = (i + 16 <= dump_size) ? 16 : (dump_size - i);
                int is_empty = 1;

                // Read the next 16 bytes (or remaining bytes)
                for (size_t j = 0; j < bytes_to_read; j++) {
                    buffer[j] = p[i + j];
                    if (buffer[j] != 0) {
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
                    fprintf(out, "%p: ", (void *)(p + i));
                    for (size_t j = 0; j < 16; j++) {
                        if (j < bytes_to_read) {
                            fprintf(out, "%02x ", buffer[j]);
                        } else {
                            fprintf(out, "   ");
                        }
                    }
                    fprintf(out, "  ");
                    for (size_t j = 0; j < 16; j++) {
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
            struct iovec local[1];
            struct iovec remote[1];
            unsigned char *buffer = (unsigned char *)malloc(dump_size);
            if (!buffer) {
                fprintf(out, "Content: Memory allocation failed\n");
                return;
            }
            local[0].iov_base = buffer;
            local[0].iov_len = dump_size;
            remote[0].iov_base = p;
            remote[0].iov_len = dump_size;
            ssize_t bytes_read = process_vm_readv(target_pid, local, 1, remote, 1, 0);
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
                        fprintf(out, "%p: ", (void *)(p + i));
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
                                fprintf(out, "%c", isprint(line_buffer[j]) ? line_buffer[j] : '.');
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
            }
            free(buffer);
        }
    } else if (target_pid == getpid()) {
        fprintf(out, "Content: Not readable (Permissions: %s)\n", s->perms);
        if (!strchr(s->perms, 'w')) {
            if (mprotect(s->base, s->size, PROT_READ) == 0) {
                fprintf(out, "Note: Temporarily set to readable to access content\n");
                size_t dump_size = filter_mode ? s->size : (s->size < 256 ? s->size : 256);
                if (filter_mode && dump_size > 1048576) { // 1 MB limit
                    dump_size = 1048576;
                    fprintf(out, "Content (hex dump, truncated to 1MB of %zu bytes):\n", s->size);
                } else {
                    fprintf(out, "Content (hex dump, %zu bytes):\n", dump_size);
                }
                unsigned char *p = (unsigned char *)s->base;
                size_t i = 0;
                size_t empty_count = 0;
                size_t last_printed = 0;

                while (i < dump_size) {
                    unsigned char buffer[16];
                    size_t bytes_to_read = (i + 16 <= dump_size) ? 16 : (dump_size - i);
                    int is_empty = 1;

                    // Read the next 16 bytes (or remaining bytes)
                    for (size_t j = 0; j < bytes_to_read; j++) {
                        buffer[j] = p[i + j];
                        if (buffer[j] != 0) {
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
                        fprintf(out, "%p: ", (void *)(p + i));
                        for (size_t j = 0; j < 16; j++) {
                            if (j < bytes_to_read) {
                                fprintf(out, "%02x ", buffer[j]);
                            } else {
                                fprintf(out, "   ");
                            }
                        }
                        fprintf(out, "  ");
                        for (size_t j = 0; j < 16; j++) {
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

                int prot = 0;
                if (strchr(s->perms, 'r')) prot |= PROT_READ;
                if (strchr(s->perms, 'w')) prot |= PROT_WRITE;
                if (strchr(s->perms, 'x')) prot |= PROT_EXEC;
                mprotect(s->base, s->size, prot);
                fprintf(out, "Note: Restored original permissions\n");
            } else {
                fprintf(out, "Note: Failed to make readable (Error: %s)\n", strerror(errno));
            }
        }
    } else {
        fprintf(out, "Content: Not readable (Permissions: %s)\n", s->perms);
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
            free_sectors(sectors, num_sectors);
            free(filters);
            return 1;
        }
    }

    if (list_sectors) {
        fprintf(out, "Number of memory sectors available for PID %d: %d\n", target_pid, num_sectors);
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

        if (!strchr(s->perms, 'w')) {
            if (mprotect(s->base, s->size, PROT_READ | PROT_WRITE) != 0) {
                fprintf(out, "Error: mprotect failed to make writable (Error: %s)\n", strerror(errno));
                free(content);
                goto cleanup;
            }
        }

        memcpy(s->base, content, fsize);

        if (!strchr(s->perms, 'w')) {
            int prot = 0;
            if (strchr(s->perms, 'r')) prot |= PROT_READ;
            if (strchr(s->perms, 'x')) prot |= PROT_EXEC;
            mprotect(s->base, s->size, prot);
        }

        free(content);
        fprintf(out, "Successfully injected content into sector %d\n", inject_sector);
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
                sleep(1);
                system("clear");
            }
        } while (is_live);
    }

cleanup:
    free_sectors(sectors, num_sectors);
    free(filters);
    if (out != stdout) {
        fclose(out);
    }
    return 0;
}