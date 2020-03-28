#include "apue.h"
#include <fcntl.h>

int
main(void)
{
	if (open("tempfile", O_RDWR) < 0)
		err_sys("open error");
	if (unlink("tempfile") < 0)
		err_sys("unlink error\n");
	
	// since here, file shouldn't have more links
	// but for delete it, kernel waits until there's no handler to open file
	printf("file unlinked\n");
	sleep(15); // sleep 15 seconds
	printf("done\n");
	exit(0);
	// now file will be deleted
}
