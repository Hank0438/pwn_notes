# pwn_notes
Somes notes about binary exploitation and writeups of pwn challenges

## Termilogy
* Buffer Overflow
  * overwrite function return address

* GOT hijack
  * if elf is PARTIAL_RELOC and its functions are dynamically resolved from external library, then its functions can be hijacked by overwrite .plt

* _fini_array / init_array overwrite
  * In the libc_start_main, there are pre-execute and post-execute functions relative to main function. It can be overwrited to any address 

* ROP
  * return to the gadgets ending with `ret` 

* JOP
  * return to the gadgets ending with `jmp` 

* Stack Pivot
  * change esp / rsp value to make more stack space for exploitation

* Format String
  * printf-related functions can be used to leak or overwrite the value in the stack

* File Descriptor Structure
  * In libc, there is a FILE* structure storing metadata for file descriptor. It can be used to arbitary write or read, or execute any functions by its vtable

## Sandbox Escape
* seccomp
* docker
* ebpf

## VM Escape
* Virtual Box
* Vmware
* Hyper-V


## Heap Exploit
* UNIX-liked
  * ptmalloc
  * jemalloc
  * tcmalloc
* WINDOWS
  * segement heap
  * NT heap

### Browser Exploit
* v8

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

## Linxu Kernel Exploit
* token stealing

## Windows Kernel Exploit
* token stealing
* token privilege overwrite

## Scripts

## Writeups
* UNIX-liked
  * pwnable.tw
* WINDOWS
  * HEVD

