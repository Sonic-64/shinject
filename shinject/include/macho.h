#ifndef MACHO_H
#define MACHO_H

#include <stdint.h>
#include "util.h"
#define LC_SEGMENT      0x1  
#define LC_SEGMENT_64   0x19 
#define LC_MAIN         0x80000028 

#define MH_MAGIC    0xFEEDFACE  
#define MH_MAGIC_64 0xFEEDFACF  


typedef int cpu_type_t;
typedef int cpu_subtype_t;

// Mach-O Header (32-bit)
struct mach_header {
    uint32_t magic;        // Mach-O magic number
    cpu_type_t cputype;    // CPU type
    cpu_subtype_t cpusubtype; // CPU subtype
    uint32_t filetype;     // Type of file (executable, library, etc.)
    uint32_t ncmds;        // Number of load commands
    uint32_t sizeofcmds;   // Size of all load commands
    uint32_t flags;        // Flags
};

// Mach-O Header (64-bit)
struct mach_header_64 {
    uint32_t magic;        // Mach-O magic number
    cpu_type_t cputype;    // CPU type
    cpu_subtype_t cpusubtype; // CPU subtype
    uint32_t filetype;     // Type of file (executable, library, etc.)
    uint32_t ncmds;        // Number of load commands
    uint32_t sizeofcmds;   // Size of all load commands
    uint32_t flags;        // Flags
    uint32_t reserved;     // Reserved
};

// Load Command
struct load_command {
    uint32_t cmd;        // Type of load command
    uint32_t cmdsize;    // Size of the command
};

// Segment Command (32-bit)
struct segment_command {
    uint32_t cmd;        // LC_SEGMENT
    uint32_t cmdsize;    // Size of this command
    char segname[16];    // Segment name
    uint32_t vmaddr;     // Virtual memory address
    uint32_t vmsize;     // Virtual memory size
    uint32_t fileoff;    // File offset
    uint32_t filesize;   // File size
    uint32_t maxprot;    // Maximum VM protection
    uint32_t initprot;   // Initial VM protection
    uint32_t nsects;     // Number of sections
    uint32_t flags;      // Flags
};

// Segment Command (64-bit)
struct segment_command_64 {
    uint32_t cmd;        // LC_SEGMENT_64
    uint32_t cmdsize;    // Size of this command
    char segname[16];    // Segment name
    uint64_t vmaddr;     // Virtual memory address
    uint64_t vmsize;     // Virtual memory size
    uint64_t fileoff;    // File offset
    uint64_t filesize;   // File size
    uint32_t maxprot;    // Maximum VM protection
    uint32_t initprot;   // Initial VM protection
    uint32_t nsects;     // Number of sections
    uint32_t flags;      // Flags
};

// Section (32-bit)
struct section {
    char sectname[16];   // Section name
    char segname[16];    // Segment name
    uint32_t addr;       // Memory address
    uint32_t size;       // Size in bytes
    uint32_t offset;     // File offset
    uint32_t align;      // Section alignment
    uint32_t reloff;     // Relocation entries offset
    uint32_t nreloc;     // Number of relocation entries
    uint32_t flags;      // Flags
    uint32_t reserved1;  // Reserved
    uint32_t reserved2;  // Reserved
};

// Section (64-bit)
struct section_64 {
    char sectname[16];   // Section name
    char segname[16];    // Segment name
    uint64_t addr;       // Memory address
    uint64_t size;       // Size in bytes
    uint32_t offset;     // File offset
    uint32_t align;      // Section alignment
    uint32_t reloff;     // Relocation entries offset
    uint32_t nreloc;     // Number of relocation entries
    uint32_t flags;      // Flags
    uint32_t reserved1;  // Reserved
    uint32_t reserved2;  // Reserved
    uint32_t reserved3;  // Reserved
};

// Entry Point Command
struct entry_point_command {
    uint32_t cmd;        // LC_MAIN
    uint32_t cmdsize;    // Size of this command
    uint64_t entryoff;   // File offset of the entry point
    uint64_t stacksize;  // Initial stack size
};


int MACH_O_inject(char *file,char *shellcode,int shellcode_len);

#endif
