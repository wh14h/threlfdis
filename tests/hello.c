#include<stdio.h>
#include<stdlib.h>
int global = 1;
int main(void) {
	int local = 2;
	printf("Hello world! Global %d Local %d\n", global, local);
	return 0;
}
