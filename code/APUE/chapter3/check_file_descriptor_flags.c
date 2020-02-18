#include "apue.h"
#include <limits.h>
#include <fcntl.h>
#include <errno.h>

int get_number_from_char(char *number);

int
main(int argc, char *argv[])
{
	int	val, fd;
	
	if (argc != 2)
		err_quit("usage: ./check_file_descriptor_flag <descriptor#>");
	
	fd = get_number_from_char(argv[1]);


	if ( (val = fcntl(fd, F_GETFL, 0)) < 0) // get file status flag
		err_sys("fcntl error for fd %d", fd);
	
	// now check all modes
	switch(val & O_ACCMODE) // check the first 3 modes of the list
	{
	case O_RDONLY:
		printf("read only");
		break;
	case O_WRONLY:
		printf("write only");
		break;
	case O_RDWR:
		printf("read write");
		break;
	default:
		err_dump("unknown access mode");
	}

	if (val & O_APPEND)
		printf(", append");
	if (val & O_NONBLOCK)
		printf(", nonblocking");
	if (val & O_SYNC)
		printf(", synchrnous writes");

	// check O_FSYNC if defined
#if !defined(_POSIX_C_SOURCE) && defined(O_FSYNC) && (O_FSYNC != O_SYNC)
	if (val & O_FSYNC)
		printf(", synchrnous writes");
#endif
	
	// end program
	putchar('\n');
	exit(0);
}


int get_number_from_char(char *number)
{
	int	return_value = 0;
	char	*bad_number = NULL;

	return_value = (int)strtol(number, &bad_number, 10);

	if (return_value == 0)
	{
		// check if a conversion error ocurred, display message and exit
		if (errno == EINVAL)
		{
			printf("conversion error ocurred: %d (%s)\n", errno, strerror(errno));

			if (bad_number != NULL)
				printf("error parsing number in: %s\n", bad_number);
			
			exit(EINVAL);
		}

		if (errno == ERANGE)
		{
			printf("value provided is out of range\n");
			exit(ERANGE);
		}
	}
	
	return return_value;
}
