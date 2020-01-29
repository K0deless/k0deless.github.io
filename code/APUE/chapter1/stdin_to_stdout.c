#include "apue.h"

#define	BUFFSIZE	4096


int
main(int argc, char *argv[])
{
	int	n;
	char	buf[BUFFSIZE];
	
	printf("[%s] PROGRAM TO READ FROM STDIN (%d)\n", argv[0], STDIN_FILENO);
	printf("WRITE TO STDOUT (%d)\n", STDOUT_FILENO);

	while ((n = read(STDIN_FILENO, buf, BUFFSIZE)) > 0)
	{
		if (write(STDOUT_FILENO, buf, n) != n)
			err_sys("write error");
	}

	if (n<0)
		err_sys("read error");
	
	exit(0);
}
