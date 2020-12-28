#include <stdio.h>

unsigned char code[] = "\xb8\x0a\x00\x00\x00\xc3";

int main(int argc, char **argv) {
    // int foo_value = (*(int(*)())code)();
    // printf("%d\n", foo_value);





    unsigned long long rax;
    __asm__ ("mov %%rax, %0":"=r"(rax):);

    printf("0x%llx\n", rax);

    
    int src = 10;    
    int dst;
    asm volatile (
        "mov %1, %0\n\t"
        "add $1, %0"
        : "=r" (dst)
        : "r" (src)
    );

    printf("0x%x\n", dst);
}