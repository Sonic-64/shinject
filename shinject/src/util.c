#include "util.h"
unsigned long align(uint32_t size, uint32_t align, uint32_t addr){
    if (!(size % align))
        return addr + size;
    return addr + (size / align + 1) * align;
}

char *load_file(char *file_name,uint32_t *size){
    char *load;
#ifdef _WIN32
    HANDLE hFile = CreateFile(file_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    *size = GetFileSize(hFile, NULL);
    if (*size == INVALID_FILE_SIZE) {

        CloseHandle(hFile);
        return NULL;
    }

    load = (char*)malloc(*size);
    if (!load) {

        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, load, *size, &bytesRead, NULL) || bytesRead != *size) {
        free(load);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    return load;
#elif
int fd = open(file_name, O_RDONLY);
if (fd == -1) {
    return NULL;
}

struct stat st;
if (fstat(fd, &st) == -1) {
    close(fd);
    return NULL;
}

*size = st.st_size;
load = malloc(*size);
if (!load) {
    close(fd);
    return NULL;
}

if (read(fd, load, *size) != *size) {
    free(load);
    close(fd);
    return NULL;
}

close(fd);
return load;
#endif
}
int file_type(char *file_name){
char buf[4];
memset(buf, 0, sizeof(buf));


FILE *f = fopen(file_name, "rb");
if (f != NULL) {

    fread(buf, sizeof(char), 4, f);
    fclose(f);

    
    if (memcmp(buf, "\x7f\x45\x4c\x46", 4) == 0) {  
        return ELF;
    }
    if (memcmp(buf, "\xce\xfa\xed\xfe", 4) == 0 ){
        return MACH_O;
    }
    if (memcmp(buf, "\xcf\xfa\xed\xfe", 4) == 0 ){
        return MACH_O;
    }
    if( memcmp(buf, "\xfe\xed\xfa\xcf", 4) == 0 ){
        return MACH_O;
    }
    if( memcmp(buf, "\xfe\xed\xfa\xcf", 4) == 0){  
        return MACH_O;;
    }
    if (memcmp(buf, "\x4d\x5a", 2) == 0) {  
        return PE;
    }
}

return -1;  // Unknown file type
}
int write_data(char *file_name,uint32_t offset , char *data, uint32_t lenght){
    #ifdef _WIN32
    HANDLE hFile = CreateFile(file_name, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }


    if (!SetFilePointer(hFile, offset, NULL, FILE_BEGIN)) {
        CloseHandle(hFile);
        return -1;
    }
    DWORD bytesWritten;
    if (!WriteFile(hFile, data, lenght, &bytesWritten, NULL)) {
        CloseHandle(hFile);
        return -1;
    }

    CloseHandle(hFile);
    return (int)bytesWritten;
    #elif 
    int fd = open(filename, O_WRONLY | O_CREAT, 0644);
    if (fd == -1) {
        perror("Failed to open file");
        return -1;
    }

    if (lseek(fd, offset, SEEK_SET) == -1) {
        close(fd);
        return -1;
    }

    ssize_t bytes_written = write(fd, data, length);
    if (bytes_written == -1) {
return -1;
    }

    close(fd);
    return bytes_written;


    #endif


}
int extend_file(char *file_name,uint32_t size){
#ifdef _WIN32
    HANDLE hFile = CreateFile(file_name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return  -1;
    }

    if (SetFilePointer(hFile, size, NULL, FILE_BEGIN) ==  INVALID_SET_FILE_POINTER){
        return -1;
    } 
    if(SetEndOfFile(hFile)==0){
        return -1;
    }    

    CloseHandle(hFile);
    return 0;

#elif
int fd = open(file_name, O_WRONLY);
if (fd == -1) {
    return -1;
}

if (ftruncate(fd, size) == -1) {
    close(fd);
    return -1;
}

close(fd);
return 0;


#endif


}
char *applysuffix(char *shellcode,int shellcode_lenght,uint32_t entry, uint32_t vaddr ){
    uint32_t entry_point = entry-(vaddr + shellcode_lenght +5);
    char *payload = malloc(shellcode_lenght + 5);

    memcpy(payload, shellcode, shellcode_lenght);
    payload[shellcode_lenght] = 0xE9; 
    *(uint32_t *)(payload + shellcode_lenght + 1) = entry; 
    return payload;
}