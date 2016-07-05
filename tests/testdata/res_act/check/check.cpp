#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);

    srand(23);
    for(int i = 0; i < 100; ++i) {
        int a = rand() % 1000;
        int b = rand() % 1000;
        int c;
        printf("%d %d\n", a, b);
        if(scanf("%d", &c) != 1) {
            return -1;
        }
        if(a + b != c) {
            return -1;
        }
    }
    return 0;
}
