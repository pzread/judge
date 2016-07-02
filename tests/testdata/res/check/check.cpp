#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main() {
    char str[100];
    char ans[100];
    FILE *ansf = fdopen(2, "r");

    FILE *fv = fopen(secure_getenv("VERDICT"), "w");

    while(fgets(str, sizeof(str), stdin) != NULL) {
        if(fgets(ans, sizeof(ans), ansf) == NULL) {
            fprintf(fv, "Failed\n");
            return -1;
        }
        if(strcmp(str, ans)) {
            fprintf(fv, "Diff\n%s\n%s\n", str, ans);
            return -1;
        }
    }
    if(fgets(ans, sizeof(ans), ansf) != NULL) {
        fprintf(fv, "Failed\n");
        return -1;
    }
    
    fprintf(fv, "Passed\n");
    fclose(fv);
    return 0;
}
