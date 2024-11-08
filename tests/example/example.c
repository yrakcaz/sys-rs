#include <stdio.h>

int main() {
    int i = 0;
    while (i < 12) {
        printf("Hello, World!\n");
        if (i == 5) {
            printf("i is 5\n");
        }
        i++;
    }
    return 0;
}
