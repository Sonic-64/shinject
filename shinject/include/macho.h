#ifndef MACHO_H
#define MACHO_H

#include <stdint.h>
#include "util.h"
#define LC_SEGMENT      0x1  
#define LC_SEGMENT_64   0x19 
#define LC_MAIN         0x80000028 
#define LC_CODE_SIGNATURE 0x1D
#define MH_MAGIC    0xFEEDFACE  
#define MH_MAGIC_64 0xFEEDFACF  


typedef int cpu_type_t;
typedef int cpu_subtype_t;


typedef struct{
    uint32_t magic;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
}mach_header;

typedef struct {
    uint32_t magic;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
}mach_header_64;


typedef struct  {
    uint32_t cmd;
    uint32_t cmdsize;
}load_command;


typedef struct  {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsec;
    uint32_t flags;
}segment_command;


typedef struct  {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsec;
    uint32_t flags;
}segment_command_64;


typedef struct {
    char secname[16];
    char segname[16];
    uint32_t addr;
    uint32_t filesize;
    uint32_t fileoff;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
}section ;

typedef struct  {
    char secname[16];
    char segname[16];
    uint64_t addr;
    uint64_t filesize;
    uint32_t fileoff;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
}section_64;


typedef struct  {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t entry_off;
    uint64_t stacksize;
}entry_point_command;

int MACH_O_sig_remove(char *file);
int MACH_O_inject(char *file,char *shellcode,int shellcode_len);

#endif
