
#include <unistd.h>
int main(void){
    const char msg[] = "syscall-write\n";
    write(1, msg, sizeof(msg) - 1);
    _exit(0);
}
