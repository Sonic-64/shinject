#ifndef UTIL_H
#include <stdio.h>
#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#elif
#include <fcntl.h>
#include <unistd.h>
#endif
#define ELF 1
#define MACH_O 2
#define PE 3
uint32_t align(uint32_t size, uint32_t align, uint32_t addr);
char *load_file(char *file_name,uint32_t *size);
int file_type(char *file_name);
int write_data(char *file_name,uint32_t offset , char *data, uint32_t lenght);
int extend_file(char *file_name,uint32_t size);
char *applysuffix(char *shellcode,int shellcode_lenght,uint32_t entry, uint32_t vaddr );


#define UTIL_H
#endif