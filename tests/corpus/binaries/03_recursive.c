
#include <stdio.h>
static int fib(int n){ return n < 2 ? n : fib(n-1) + fib(n-2); }
static int is_even(int n){ return n == 0 ? 1 : !is_even(n-1); }
int main(void){ printf("%d %d\n", fib(10), is_even(8)); return 0; }
