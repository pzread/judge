#include<stdio.h>
#include<stdlib.h>

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);

    int a, b;
    while(scanf("%d %d", &a, &b) == 2) {
        printf("%d\n", a + b);
    }
    return 0;
}
