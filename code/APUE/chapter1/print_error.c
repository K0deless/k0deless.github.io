#include "apue.h"	// apue header
#include <errno.h>	// errno header for errors

int
main(int argc, char *argv[])
{
	fprintf(stderr, "EACCES error string and value: %s(%ld)\n", strerror(EACCES), (long) EACCES); // get string of error, with function strerror
	errno = ENOENT; // set errno exported variable to ENOENT error number
	perror(argv[0]); // print string error, with program name as prefix
	exit(0);
}
