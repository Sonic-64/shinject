#ifndef ELF_H
#define ELF_H
#include <stdint.h>
#include "util.h"
#define ELFCLASS32 1
#define ELFCLASS64 2
#define ET_EXEC 2
#define PF_X 1
#define PF_W 2
#define PF_R 4
#define PT_LOAD 1
typedef struct {
    unsigned char   e_ident[16];
    uint16_t      e_type;
    uint16_t      e_machine;
    uint32_t      e_version;
    uint32_t      e_entry;
    uint32_t      e_phoff;
    uint32_t      e_shoff;
    uint32_t      e_flags;
    uint16_t      e_ehsize;
    uint16_t      e_phentsize;
    uint16_t      e_phnum;
    uint16_t      e_shentsize;
    uint16_t      e_shnum;
    uint16_t      e_shstrndx;
} Elf32_Ehdr;

typedef struct
{
uint32_t    p_type;                 
uint32_t    p_offset;               
uint32_t    p_vaddr;                
uint32_t    p_paddr;                
uint32_t    p_filesz;               
uint32_t    p_memsz;                
uint32_t    p_flags;                
uint32_t    p_align;                
} Elf32_Phdr;

typedef struct
{
uint32_t    sh_name;                
uint32_t    sh_type;                
uint32_t    sh_flags;               
uint32_t    sh_addr;                
uint32_t    sh_offset;              
uint32_t    sh_size;                
uint32_t    sh_link;               
uint32_t    sh_info;                
uint32_t    sh_addralign;          
uint32_t    sh_entsize;             
} Elf32_Shdr;
typedef struct {
    unsigned char   e_ident[16];    /* Magic number and other info */
    uint16_t        e_type;         /* Object file type */
    uint16_t        e_machine;      /* Architecture */
    uint32_t        e_version;      /* Object file version */
    uint64_t        e_entry;        /* Entry point virtual address */
    uint64_t        e_phoff;        /* Program header table file offset */
    uint64_t        e_shoff;        /* Section header table file offset */
    uint32_t        e_flags;        /* Processor-specific flags */
    uint16_t        e_ehsize;       /* ELF header size in bytes */
    uint16_t        e_phentsize;    /* Program header table entry size */
    uint16_t        e_phnum;        /* Program header table entry count */
    uint16_t        e_shentsize;    /* Section header table entry size */
    uint16_t        e_shnum;        /* Section header table entry count */
    uint16_t        e_shstrndx;     /* Section header string table index */
} Elf64_Ehdr;
typedef struct {
    uint32_t    p_type;             /* Segment type */
    uint32_t    p_flags;            /* Segment flags */
    uint64_t    p_offset;           /* Segment file offset */
    uint64_t    p_vaddr;            /* Segment virtual address */
    uint64_t    p_paddr;            /* Segment physical address */
    uint64_t    p_filesz;           /* Segment size in file */
    uint64_t    p_memsz;            /* Segment size in memory */
    uint64_t    p_align;            /* Segment alignment */
} Elf64_Phdr;
typedef struct {
    uint32_t    sh_name;            /* Section name (string tbl index) */
    uint32_t    sh_type;            /* Section type */
    uint64_t    sh_flags;           /* Section flags */
    uint64_t    sh_addr;            /* Section virtual addr at execution */
    uint64_t    sh_offset;          /* Section file offset */
    uint64_t    sh_size;            /* Section size in bytes */
    uint32_t    sh_link;            /* Link to another section */
    uint32_t    sh_info;            /* Additional section information */
    uint64_t    sh_addralign;       /* Section alignment */
    uint64_t    sh_entsize;         /* Entry size if section holds table */
} Elf64_Shdr;
int ELF_inject(char *file,char *shellcode, int shellcode_len);
#endif