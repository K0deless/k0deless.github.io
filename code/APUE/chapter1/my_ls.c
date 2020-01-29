#include "apue.h" // header from apue book with some useful functions
#include <dirent.h> // header for directory management

int
main (int argc, char *argv[])
{
	DIR	*dp;		// handler for directory
	struct dirent	*dirp;	// structure with directory information
	
	printf("[%s] PROGRAM SIMPLE COPY OF LS",argv[0]);

	if (argc != 2)
		err_quit("usage: %s directory_name", argv[0]);

	if ((dp = opendir(argv[1])) == NULL) // open the directory to manage
		err_sys("can't open %s", argv[1]);
	while ((dirp = readdir(dp)) != NULL) // start reading it
	{
		printf("%s\n", dirp->d_name);
	}

	closedir(dp); // close the directory fd
	exit(0);
}

