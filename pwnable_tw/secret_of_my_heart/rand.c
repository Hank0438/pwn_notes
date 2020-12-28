#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]){
    /*
    int i = 0;
    for (i = 0; i < 50; i++) {
        time_t t = time(NULL);
        printf("seed: %d\n", t);
        srand(t);
        printf("rand: %x\n", rand() & 0xFFFFF000);
        sleep(1);
    }
    */
    srand((time_t)atoi(argv[1]));
    printf("rand: %x\n", rand() & 0xFFFFF000);
    return 0;
}