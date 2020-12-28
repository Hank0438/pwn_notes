#include <stdio.h>
#include <stdlib.h>

int target = 0xdeadbeef;

int main()
{   
    int a[20] = {0xdeadbeef};
    int index,value;
    printf("a at %p\n",a);
    printf("target at %p\n",&target);
    scanf("%d%d", &index, &value);
    a[index] = value;
    if (target == 0x27)
        printf("Congratulations!\n");
    else
    {
        printf("try again.\n");
    }
    return 0;
}