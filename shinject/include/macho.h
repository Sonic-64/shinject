#ifndef MACHO_H
#define MACHO_H

#include <stdint.h>
#include "util.h"
#define LC_SEGMENT      0x1  
#define LC_SEGMENT_64   0x19 
#define LC_MAIN         0x80000028 
#define LC_CODE_SIGNATURE 0x1D
#define	LC_SYMTAB	0x2
#define	LC_DYSYMTAB	0xb
#define	LC_TWOLEVEL_HINTS 0x16
#define LC_SEGMENT_SPLIT_INFO 0x1e
#define LC_FUNCTION_STARTS 0x26
#define LC_DATA_IN_CODE 0x29
#define LC_DYLIB_CODE_SIGN_DRS 0x2B
#define LC_LINKER_OPTIMIZATION_HINT 0x2E
#define LC_REQ_DYLD 0x80000000
#define LC_DYLD_EXPORTS_TRIE (0x33 | LC_REQ_DYLD)
#define LC_DYLD_CHAINED_FIXUPS (0x34 | LC_REQ_DYLD)
#define LC_FILESET_ENTRY      (0x35 | LC_REQ_DYLD)
#define MH_MAGIC    0xFEEDFACE  
#define MH_MAGIC_64 0xFEEDFACF  


typedef int cpu_type_t;
typedef int cpu_subtype_t;
union lc_str {
    uint32_t	offset;	/* offset to the string */
    #ifndef __LP64__
    char		*ptr;	/* pointer to the string */
    #endif
};

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
typedef struct  {
    uint32_t	cmd;
    uint32_t	cmdsize;
    uint32_t	symoff;
    uint32_t	nsyms;
    uint32_t	stroff;
    uint32_t	strsize;
}symtab_command;
typedef struct  {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t iundefsym;
    uint32_t nundefsym;
    uint32_t tocoff;
    uint32_t ntoc;
    uint32_t modtaboff;
    uint32_t nmodtab;
    uint32_t extrefsymoff;
    uint32_t nextrefsyms;
    uint32_t indirectsymoff;
    uint32_t nindirectsyms;
    uint32_t extreloff;
    uint32_t nextrel;
    uint32_t locreloff;
    uint32_t nlocrel;

}dysymtab_command;
typedef struct  {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t offset;
    uint32_t nhints;
}twolevel_hints_command;
typedef struct  {
    uint32_t	cmd;
    uint32_t	cmdsize;
    uint32_t	dataoff;
    uint32_t	datasize;
}linkedit_data_command;
typedef struct  {
    uint32_t        cmd;
    uint32_t        cmdsize;
    uint64_t        vmaddr;
    uint64_t        fileoff;
    union lc_str    entry_id;
    uint32_t        reserved;
}fileset_entry_command;
int MACH_O_sign(char *file,char *signature);
int MACH_O_sig_remove(char *file);
int MACH_O_inject(char *file,char *shellcode,int shellcode_len);

#endif
