#include "apue.h"

int
main(int argc, char *argv[])
{
	char	*ptr;
	size_t	size;

	if ( argc != 2 )
	{
		printf("usage: %s <directory>\n", argv[0]);
		exit(0);
	}

	if (chdir(argv[1]) < 0)
		err_sys("chdir failed");
	
	ptr = path_alloc(&size);	// our own function
	if (getcwd(ptr, size) == NULL)
		err_sys("getcwd failed");
	
	printf("cwd = %s\n", ptr);
	exit(0);
}
