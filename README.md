shinject is a C based shellcode injection library currently supporting 32bit and 64bit MACH-O/ELF/PE

## Building from source:  
git clone https://github.com/Sonic-64/shinject.git  
cd shinject  
cd shinject  
mkdir build && cd build  
cmake ..  
make  
## Usage:

./shinject_main [options]  

Options:  
-rm <file_name> remove a signature from file 
-i <file_name> <shellcode_file> inject a shellcode to file  

