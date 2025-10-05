# Arachnid - Memory Inspection Tool

**Arachnid** is a cross-platform command-line tool for inspecting and manipulating process memory. It provides detailed insights into a process's memory layout, allowing users to view memory sectors, their attributes, and contents in a hex dump format. Designed for developers, security researchers, and system administrators, Arachnid supports Windows, Linux, macOS, Android, and iOS, with platform-specific optimizations to handle memory access and permissions.

## Key Features
- **Memory Inspection**: Displays memory sectors for a specified process (or the current process by default), including base address, size, permissions, and type.
- **Hex Dump Output**: Shows memory contents in a hex and ASCII format, with a 1 MB limit per sector in filter mode to prevent excessive output.
- **Filter Mode**: Use the `-f` or `--filter` option to focus on specific memory sectors, with optional `--show-null=true` to display all lines, including those with all zeros (default collapses empty lines with `...(N)`).
- **Memory Injection**: Supports injecting content from a file into a memory sector of the current process (not available on Android/iOS due to security restrictions).
- **Live Updates**: Continuously refreshes memory output when directed to stdout, useful for monitoring dynamic changes.
- **Cross-Platform Support**: Tailored implementations for Windows (`ReadProcessMemory`), Linux/Android (`process_vm_readv`), and macOS/iOS (`mach_vm_read_overwrite`).

### Arguments available:
```
-f --filter    | filter to X sector
    --show-null=bool  | toggle null data filter
-p --process   | filter to PID
--list-sectors | show sectors used by the process. use -p if you want to check another process' sectors
```

### Example usage:
```bash
$ arachnid -p 1008 --list-sectors
Number of memory sectors available for PID 1008: 1650

$ arachnid -p 1008 -f 29
Sun Oct  5 12:35:49 2025

Sector 29:
PID: 1008
Base: 0000006BAA7FA000
Size: 12288
State: MEM_COMMIT (0x1000)
Protect: Other (0x104)
Type: MEM_PRIVATE (0x20000)
Content (hex dump, 12288 bytes):
...(768)    # This happens when all data in that sector is 00. you can turn null filters off with the args --show-null=true while --filter/-f is used
```



Arachnid is ideal for debugging, reverse engineering, or analyzing memory usage, but requires appropriate permissions (e.g., root or admin for cross-process access). Use responsibly and ensure compliance with applicable laws and security policies.

The `android.mk` file is for those who want to run the script on an android device.
