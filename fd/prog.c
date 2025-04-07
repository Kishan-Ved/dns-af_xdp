#include <stdio.h>
#include <unistd.h>

int main()
{
    /*
    FILE DESCRIPTORS
    0 - stdin
    1 - stdout
    2 - stderr
    
    SYSTEM CALLS
    0 - read
    1 - write
    2 - open
    3 - close
    */
    write(1, "Hello, World!\n", 14);    // printf("Hello, World!\n");

    int a;
    read(0, &a, sizeof(int));    // scanf("%d", &a);
    write(1, &a, sizeof(int));    // printf("%d", a);
    return 0;
}