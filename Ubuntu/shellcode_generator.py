import os, sys
import subprocess

def gen_loader():
    code = "\\xb8\\x0a\\x00\\x00\\x00\\xc3"
    shellcode_loader_header = '''
    #include <stdio.h>

    unsigned char code[] = "{}";
    '''.format(code)

    shellcode_loader_body = '''

    int main(int argc, char **argv) {
        int foo_value = (*(int(*)())code)();
        printf("%d\\n", foo_value);
    }
    '''
    shellcode_loader = shellcode_loader_header + shellcode_loader_body

    shellcode_loader = '''
    #include <stdio.h>

    int main(int argc, char **argv) {

        unsigned long long rax;
        __asm__ ("mov %%rax, %0":"=r"(rax):);

        printf("0x%llx\\n", rax);

        
        int src = 10;    
        int dst;
        asm volatile (
            "mov %1, %0\\n\\t"
            "add $1, %0"
            : "=r" (dst)
            : "r" (src)
        );

        printf("0x%x\\n", dst);
    }
    '''

    return shellcode_loader

def gen_loaderfile():
    filename = "./shellcode_loader123"
    shellcode_loader = gen_loader()

    new_file = open(filename+".c","w")
    new_file.write(shellcode_loader)
    new_file.close()

    compile_cmd = "gcc -fno-stack-protector -z execstack {src_file} -o {output_file}".format(src_file=filename+".c", output_file=filename)
    subprocess.call(compile_cmd, shell=True)

    exec_cmd = filename
    subprocess.call(exec_cmd, shell=True)

    subprocess.call("rm "+filename, shell=True)

def gen_makefile():
    pass

if __name__ == '__main__':
    gen_loaderfile()