#include "apue.h"
#include <fcntl.h>

int
main(int argc, char *argv[])
{
	int		i, fd;
	struct stat	statbuf;
	struct timespec	times[2];

	for (i = 1; i < argc; i++)
	{
		printf("\ndestroying silently the file %s...", argv[i]);

		if (stat(argv[i], &statbuf) < 0) // get current times
		{
			err_ret("%s: stat error", argv[i]);
			continue;
		}

		if ( (fd = open(argv[i], O_RDWR | O_TRUNC)) < 0) // truncate file
		{
			err_ret("%s: open error", argv[i]);
			continue;
		}

		times[0] = statbuf.st_atim;
		times[1] = statbuf.st_mtim;
		
		if (futimens(fd, times) < 0)	// reset times
		{
			err_ret("%s: futimens error", argv[i]);
		}
		
		printf("destroyed successfuly");

		close(fd);
	}
	printf("\n\n");
	exit(0);
}
