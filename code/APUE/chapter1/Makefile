CC=gcc -g3 -Wall
libDir=/home/Fare9/Documents/APUE/apue.3e/lib/
includeDir=/home/Fare9/Documents/APUE/apue.3e/include/
objectFolder=./objF9/
binFolder=./binF9/
MKDIR_P=mkdir -p

.PHONY: directories clean remove

all: directories $(binFolder)my_ls $(binFolder)stdin_to_stdout $(binFolder)standard_stdin_to_stdout \
	$(binFolder)print_pid $(binFolder)very_simple_shell $(binFolder)print_error \
	$(binFolder)get_ids $(binFolder)sig_int_catch

$(binFolder)my_ls: $(objectFolder)my_ls.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)my_ls $(objectFolder)my_ls.o -lapue 

$(objectFolder)my_ls.o: my_ls.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)my_ls.o my_ls.c

$(binFolder)stdin_to_stdout: $(objectFolder)stdin_to_stdout.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)stdin_to_stdout $(objectFolder)stdin_to_stdout.o -lapue

$(objectFolder)stdin_to_stdout.o: stdin_to_stdout.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)stdin_to_stdout.o stdin_to_stdout.c

$(binFolder)standard_stdin_to_stdout: $(objectFolder)standard_stdin_to_stdout.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)standard_stdin_to_stdout $(objectFolder)standard_stdin_to_stdout.o -lapue

$(objectFolder)standard_stdin_to_stdout.o: standard_stdin_to_stdout.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)standard_stdin_to_stdout.o standard_stdin_to_stdout.c

$(binFolder)print_pid: $(objectFolder)print_pid.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)print_pid $(objectFolder)print_pid.o -lapue

$(objectFolder)print_pid.o: print_pid.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)print_pid.o print_pid.c

$(binFolder)very_simple_shell: $(objectFolder)very_simple_shell.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)very_simple_shell $(objectFolder)very_simple_shell.o -lapue

$(objectFolder)very_simple_shell.o: very_simple_shell.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)very_simple_shell.o very_simple_shell.c

$(binFolder)print_error: $(objectFolder)print_error.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)print_error $(objectFolder)print_error.o -lapue

$(objectFolder)print_error.o: print_error.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)print_error.o print_error.c

$(binFolder)get_ids: $(objectFolder)get_ids.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)get_ids $(objectFolder)get_ids.o -lapue

$(objectFolder)get_ids.o: get_ids.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)get_ids.o get_ids.c

$(binFolder)sig_int_catch: $(objectFolder)sig_int_catch.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)sig_int_catch $(objectFolder)sig_int_catch.o -lapue

$(objectFolder)sig_int_catch.o: sig_int_catch.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)sig_int_catch.o sig_int_catch.c
#################################################################
# Clean but don't remove directories
#################################################################
clean:
	rm -rf $(objectFolder)*.o
	rm -rf $(binFolder)my_ls
	rm -rf $(binFolder)stdin_to_stdout
	rm -rf $(binFolder)standard_stdin_to_stdout
	rm -rf $(binFolder)print_pid
	rm -rf $(binFolder)very_simple_shell
	rm -rf $(binFolder)print_error
	rm -rf $(binFolder)get_ids

##################################################################
# Remove everything
##################################################################

remove:
	rm -rf $(objectFolder)
	rm -rf $(binFolder)

###################################################################
# Create the directories
###################################################################
directories: $(objectFolder) $(binFolder)

$(objectFolder):
	$(MKDIR_P) $(objectFolder)

$(binFolder):
	$(MKDIR_P) $(binFolder)
