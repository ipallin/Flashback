
#include <stdio.h>
#include <string.h>
int main(void){
    char buf[64];
    const char *a = "Flash", *b = "back";
    snprintf(buf, sizeof buf, "%s%s", a, b);
    strcat(buf, "!");
    printf("%s len=%zu\n", buf, strlen(buf));
    return 0;
}
