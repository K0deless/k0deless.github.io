#include "apue.h"
#include <fcntl.h>

int
main(int argc, char *argv[])
{
	if (argc != 2)
		err_quit("usage: %s <pathname>", argv[0]);
	
	if (access(argv[1], F_OK) < 0)
		err_ret("file %s does not exist", argv[1]);
	else
		printf("file exist\n");
	
	/*
	*	Second argument can be:
	*		R_OK	test for read permission
	*		W_OK	test for write permission
	*		X_OK	test for execute permission
	*
	*
	*	Here even if bit SUID is used as root, checking
	*	/etc/passwd or /etc/spwd.db with access
	*	function it will raise an error, and "access error"
	*	will be printed.
	*/
	if (access(argv[1], R_OK) < 0)
		err_ret("access error for %s", argv[1]);
	else
		printf("read access OK\n");

	if (open(argv[1], O_RDONLY) < 0)
		err_ret("open error for %s", argv[1]);
	else
		printf("open for reading OK\n");

	exit(0);
	
}
