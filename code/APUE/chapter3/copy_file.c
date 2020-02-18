#include "apue.h"

#define BUFFSIZE 4096

int
main (void)
{
	int	n;
	char	buf[BUFFSIZE];

	while ((n = read(STDIN_FILENO, buf, BUFFSIZE)) > 0) // read from STDIN until the end
		if ( write(STDOUT_FILENO, buf, n) != n ) // write to stdout every read byte
			err_sys("write error");
	
	if ( n < 0 ) // if at the end n is lower than 0, there was an error
		err_sys("read error");

	exit (0);
}
