#include "apue.h"
#include <fcntl.h>

// mask that represents read/write for everyone
#define RWRWRW (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)

int
main(void)
{
	umask(0); // allow everything in file creation
	if (open("foo", O_CREAT | O_TRUNC | O_WRONLY, RWRWRW) < 0)
		err_sys("create file error for foo");
	
	// now avoid read/write for group and others
	umask (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

	if (open("bar", O_CREAT | O_TRUNC | O_WRONLY, RWRWRW) < 0)
		err_sys("create file error for bar");
	
	exit(0);
}

