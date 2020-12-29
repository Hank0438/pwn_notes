# pwn_notes
This is a note and POC for some basic pwn technique. 

## Userland
### Exploit
| Technique | Description | Linux | Windows | 
| -------- | -------- | -------- | -------- |
| Buffer Overflow     |      |      |      |
| GOT hijack     |      |      |      |
| _fini_array overwrite     |      |      |      |
| Return Of Object Programming     |      |      |      |
| Stack Pivot     |      |      |      |
| Format String     |      |      |      |
| File Descripter Structure |      |      |      |

### Heap Exploit
* UNIX-liked
  * ptmalloc
  * jemalloc
  * tcmalloc
* WINDOWS
  * segement heap
  * NT heap


### Protection
* UNIX-liked
  * NX
  * PIE
  * ASLR
  * RELRO
    * FULL:     
    * PARTIAL:  GOT can write
    * DISABLE:  
  * CANARY: STACK smash detect
  * FORTIFY
* WINDOWS
  * DEP
  * CFG
  * Authenticode
### Information Leak
* UNIX-liked
  * PIE
  * ASLR
    * stack_addr
    * libc_base -> libc_function_offset
* WINDOWS
  * image_base
  * dll_image_base -> dll_export_function_offset

## Kernel
* UNIX-liked
* WINDOWS
  * token stealing

## Scripts

## Writeups
* UNIX-liked
  * pwnable.tw
* WINDOWS
  * HEVD

