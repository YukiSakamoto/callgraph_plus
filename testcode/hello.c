#include <stdio.h>

int global_variable = 10;
int global_variable_uninitialized;
const int constant_global_variable = 10;


void say_goodnight(void) {
	printf("good night!\n");
}

void say_hello(void)
{
	int i = constant_global_variable;
	for(i = 0; i < 5; i++) {
		printf("hello world\n");
	}
	say_goodnight();
}

int main(void)
{
	say_hello();
	say_hello();
	say_hello();
	return 0;
}
