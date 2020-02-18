#include "apue.h" // our apue header with many of the others headers

int
main (void)
{
	if ( lseek(STDIN_FILENO, 0, SEEK_CUR) == -1 )
		printf("File descriptor STDIN_FILENO(%d) cannot seek\n", STDIN_FILENO);
	else
		printf("seek OK\n");
	exit(0);
}
