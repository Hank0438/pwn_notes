# pwnable_tw_writeup

## start

### observation
* buffer overflow
* sys_exec

### steps
1. leak esp
2. push shellcode exec "/bin/sh"

## orw

### observation
* execute stack
* only file ORW works

### steps
1. push shellcode exec file open, file read, and then file write to stdout

## calc

### observation
* stack is writeable and somehow the program can be crashed by overwriting the specific position of stack

### steps


## 3x17

### observation


### steps
