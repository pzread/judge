#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main() {
    char str[100];
    char ans[100];
    FILE *ansf = fdopen(2, "r");
    while(gets(str) != NULL) {
        if(fgets(ans, sizeof(ans), ansf) == NULL) {
            return -1;
        }
        if(ans[strlen(ans) - 1] == '\n') {
            ans[strlen(ans) - 1] = '\0';
        }
        if(strcmp(str, ans)) {
            return -1;
        }
    }
    if(fgets(ans, sizeof(ans), ansf) != NULL) {
        return -1;
    }
    return 0;
}
