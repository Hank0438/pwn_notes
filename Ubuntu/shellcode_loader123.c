
    #include <stdio.h>

    int main(int argc, char **argv) {

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
    