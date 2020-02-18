#include "apue.h"
#include <fcntl.h> // necessary for creat function

#define FILE_NAME "file.hole"

char	buf1[] = "abcdefghij";
char	buf2[] = "ABCDEFGHIJ";

int
main (void)
{
	int	fd;

	if ( (fd = creat(FILE_NAME, FILE_MODE)) < 0)
		err_sys("creat error");
	
	if (write(fd, buf1, 10) != 10) // first write, check was correct
		err_sys("buf1 write error");
	/* offset is now = 10 */

	if (lseek(fd, 16384, SEEK_SET) == -1) // create big hole from the beginning
		err_sys("lseek error");
	/* offset is now = 16384 */

	if (write(fd, buf2, 10) != 10)
		err_sys("buf2 write error");
	/* offset is now = 16394 */

	exit(0);
}
