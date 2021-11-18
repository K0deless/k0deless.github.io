/***
 * Debugger with possibility to attach
 *	to a 64 bit process.
 */

// headers
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>         // Posix header
#include <fcntl.h>
#include <errno.h>          // Standard errors
#include <signal.h>         // Unix signals
#include <elf.h>            // ELF headers
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>       // file stats
#include <sys/ptrace.h>     // ptrace debugging syscall
#include <sys/mman.h>       // memory mapping


#define EXE_MODE 0
#define PID_MODE 1


typedef struct handle 
{
    Elf64_Ehdr*     ehdr;
    Elf64_Phdr*     phdr;
    Elf64_Shdr*     shdr;
    uint8_t*        mem;
    char*           symname;
    Elf64_Addr      symaddr;
    struct user_regs_struct pt_reg;
    char*           exec;
} handle_t;


int global_pid;

Elf64_Addr lookup_symbol(handle_t *, const char *);
char * get_exe_name(int);
void sighandler(int);


int
main (int argc, char **argv, char **envp)
{
	int fd, c, mode = 0;
	handle_t h;
	struct stat st;
	long trap, orig;
	int status, pid;
	char * args[2];

	if (argc < 2)
	{
		printf("Usage: %s [-p <pid> or -e <exe>] [-f <func_name>]\n", argv[0]);
		exit(0);
	}

	memset(&h, 0, sizeof(handle_t));

	while ((c = getopt(argc, argv, "p:e:f:")) != -1)
	{
		switch(c)
		{
		case 'p':
			pid = atoi(optarg);
			h.exec = get_exe_name(pid);
			if (h.exec == NULL)
			{
				printf("Unable to retrieve executable path for pid: %d\n", pid);
				exit(-1);
			}
			mode = PID_MODE;
			break;
		case 'e':
			if ((h.exec = strdup(optarg)) == NULL)
			{
				perror("strdup");
				exit(-1);
			}

			mode = EXE_MODE;
			break;
		case 'f':
			if ((h.symname = strdup(optarg)) == NULL)
			{
				perror("strdup");
				exit(-1);
			}
			break;
		default:
			printf("Unknown option\n");
			break;
		}
	}

	if (h.symname == NULL)
	{
		printf("Specifying a function name with -f option is required\n");
		exit(-1);
	}

	if (mode == EXE_MODE)
	{
		args[0] = h.exec;
		args[1] = NULL;
	}

	signal(SIGINT, sighandler);

	if ((fd = open(h.exec, O_RDONLY)) < 0)
	{
        fprintf(stderr,"Error opening file %s\n", h.exec);
		perror("open");
		exit(-1);
	}

	if (fstat(fd, &st) < 0)
	{
		perror("fstat");
		exit(-1);
	}

	h.mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (h.mem == MAP_FAILED)
	{
		perror("mmap");
		exit(-1);
	}

	h.ehdr = (Elf64_Ehdr *)h.mem;

    if(h.mem[0] != 0x7f || h.mem[1] != 'E' || h.mem[2] != 'L' || h.mem[3] != 'F')
    {
        fprintf(stderr, "%s is not an ELF file\n", h.exec);
        exit(-2);
    }

    if (h.ehdr->e_phoff > st.st_size)
    {
        printf("Error e_phoff(%08X) greater than file size(%08XB)\n", (unsigned int)h.ehdr->e_phoff, (unsigned int)st.st_size);
        exit(-2);
    }

    if (h.ehdr->e_shoff > st.st_size)
    {
        fprintf(stderr, "Error e_shoff(%08X) greater than file size(%08XB)\n", (unsigned int)h.ehdr->e_shoff, (unsigned int)st.st_size);
        exit(-2);
    }

    if (h.ehdr->e_machine != EM_IA_64 && h.ehdr->e_machine != EM_X86_64)
    {
        fprintf(stderr, "Only supported x86_64 elf binaries\n");
        exit(-2);
    }


    h.phdr = (Elf64_Phdr *)(h.mem + h.ehdr->e_phoff);
    h.shdr = (Elf64_Shdr *)(h.mem + h.ehdr->e_shoff);

    if (h.ehdr->e_type != ET_EXEC)
    {
        fprintf(stderr, "%s is not an ELF executable\n", h.exec);
        exit(-1);
    }

    // check if there's not offset to string table
    // or there's not section offset
    // or there's not section numbers
    if (h.ehdr->e_shstrndx == 0 || h.ehdr->e_shoff == 0 || h.ehdr->e_shnum == 0)
    {
        fprintf(stderr, "Section header table not found\n");
        exit(-1);
    }

    if ((h.symaddr = lookup_symbol(&h, h.symname)) == 0)
    {
        fprintf(stderr, "Unable to find symbol: %s not found in executable\n", h.symname);
        exit(-1);
    }

    close(fd);

    if (mode == EXE_MODE)
    {
    	if ((pid = fork()) < 0)
    	{
    		perror("fork");
    		exit(-1);
    	}

    	if (pid == 0)
    	{
    		if (ptrace(PTRACE_TRACEME, pid, NULL, NULL) < 0) // ptrace own process (will be catched by parent process)
	        {
	            perror("PTRACE_TRACEME");
	            exit(-1);
	        }

	        execve(h.exec, args, envp); // execute new process, never return (this is like creating a process suspended in windows)
	        exit(0);
    	}
    }
    else // mode == PID_MODE
    {
    	// attach to process 'pid'
    	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
    	{
    		perror("PTRACE_ATTACH");
    		exit(-1);
    	}
    }
    wait(&status); // wait tracee to stop
    global_pid = pid;
    printf("Beginning analysis of pid: %d at %lx\n", pid, h.symaddr);
    // Read the 8 bytes at h.symaddr
    if ((orig = ptrace(PTRACE_PEEKTEXT, pid, h.symaddr, NULL)) < 0)
    {
    	perror("PTRACE_PEEKTEXT");
    	exit(-1);
    }

    // set a breakpoint
    trap = (orig & ~0xff) | 0xcc;

    printf("Setting breakpoint in: %x\n", h.symaddr);
    // write breakpoint to instruction
    if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, trap) < 0)
    {
    	perror("PTRACE_POKETEXT");
    	exit(-1);
    }

    printf("Breakpoint success\n");
    // Begin tracing execution
trace:
	
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0)
	{
		perror("PTRACE_CONT");
		exit(-1);
	}

	wait(&status);

	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
    {
        // get registers from program
        if (ptrace(PTRACE_GETREGS, pid, NULL, &h.pt_reg) < 0)
        {
            perror("PTRACE_GETREGS");
            exit(-1);
        }

        printf("\nExecutable %s (pid: %d) has hit breakpoint 0x%lx\n", h.exec, pid, h.symaddr);
        printf("%%rcx: %016x\t%%rdx: %016x\t%%rbx: %016x\n"
               "%%rax: %016x\t%%rdi: %016x\t%%rsi: %016x\n"
               "%%r8:  %016x\t%%r9:  %016x\t%%r10: %016x\n"
               "%%r11: %016x\t%%r12: %016x\t%%r13: %016x\n"
               "%%r14: %016x\t%%r15: %016x\t%%rsp: %016x\n"
               "%%rbp: %016x\n",
               h.pt_reg.rcx, h.pt_reg.rdx, h.pt_reg.rbx,
               h.pt_reg.rax, h.pt_reg.rdi, h.pt_reg.rsi,
               h.pt_reg.r8, h.pt_reg.r9, h.pt_reg.r10,
               h.pt_reg.r11, h.pt_reg.r12, h.pt_reg.r13,
               h.pt_reg.r14, h.pt_reg.r15, h.pt_reg.rsp,
               h.pt_reg.rbp);
        printf("\nPlease hit any key to continue: ");
        getchar();
        // set original byte to address where we set breakpoint
        if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, orig) < 0)
        {
            perror("PTRACE_POKETEXT");
            exit(-1);
        }
        // fix rip to point beginning of the instruction
        h.pt_reg.rip = h.pt_reg.rip - 1;
        // set new value fo registers
        if (ptrace(PTRACE_SETREGS, pid, NULL, &h.pt_reg) < 0)
        {
            perror("PTRACE_SETREGS");
            exit(-1);
        }
        // single step in order to set again the breakpoint
        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
        {
            perror("PTRACE_SINGLESTEP");
            exit(-1);
        }
        wait(NULL); // wait until single step has finished
        if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, trap) < 0)
        {
            perror("PTRACE_POKETEXT");
            exit(-1);
        }

        goto trace;
    }

    if (WIFEXITED(status))
        printf("Completed tracing pid: %d\n", pid);
    exit(0);

}


Elf64_Addr 
lookup_symbol(handle_t *h, const char *symname)
{
    int         i, j;
    char*       strtab;
    Elf64_Sym*  symtab;

    for (i = 0; i < h->ehdr->e_shnum; i++)
    {
        if (h->shdr[i].sh_type == SHT_SYMTAB)
        {
            strtab = (char *)&h->mem[h->shdr[h->shdr[i].sh_link].sh_offset];
            symtab = (Elf64_Sym *)&h->mem[h->shdr[i].sh_offset];
            for (j = 0; j < h->shdr[i].sh_size/sizeof(Elf64_Sym); j++)
            {
                if (strcmp(&strtab[symtab->st_name], symname) == 0)
                    return (symtab->st_value);
                symtab++;
            }
        }
    }

    return 0;
}

/*
*	Function to parse cmdline proc entry to retrieve
*	the executable name of the process
*
* Example taken from ``Learning Linux Binary Analysis'' book
*/

char*
get_exe_name(int pid)
{
	char cmdline[255], path[512], *p;
	int fd;
	snprintf(cmdline, 255, "/proc/%d/cmdline", pid);

	if ((fd = open(cmdline, O_RDONLY)) < 0)
	{
        fprintf(stderr, "Error opening file %s\n", cmdline);
		perror("open");
		exit(-1);
	}

	if (read(fd, path, 512) < 0)
	{
		perror("read");
		exit(-1);
	}

	if ((p = strdup(path)) == NULL)
	{
		perror("strdup");
		exit(-1);
	}

	return p;
}


void 
sighandler(int sig)
{
	printf("Caught SIGINT: Detaching from %d\n", global_pid);
	if (ptrace(PTRACE_DETACH, global_pid, NULL, NULL) < 0 && errno)
	{
		perror("PTRACE_DETACH");
		exit(-1);
	}

	exit(0);
}
