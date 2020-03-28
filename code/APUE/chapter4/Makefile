CC=gcc -g3 -Wall
libDir=/home/Fare9/Documents/APUE/apue.3e/lib/
includeDir=/home/Fare9/Documents/APUE/apue.3e/include/
objectFolder=./objF9/
binFolder=./binF9/
MKDIR_P=mkdir -p

.PHONY: directories clean remove 

all: directories $(binFolder)type_printer $(binFolder)real_user_check \
	$(binFolder)create_files_umask $(binFolder)change_file_permissions\
	$(binFolder)unlink_tempfile $(binFolder)silent_change \
	$(binFolder)path_traverser $(binFolder)change_chdir \
	$(binFolder)get_current_dir 

$(binFolder)type_printer: $(objectFolder)type_printer.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)type_printer $(objectFolder)type_printer.o -lapue

$(objectFolder)type_printer.o: type_printer.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)type_printer.o type_printer.c

$(binFolder)real_user_check: $(objectFolder)real_user_check.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)real_user_check $(objectFolder)real_user_check.o -lapue

$(objectFolder)real_user_check.o: real_user_check.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)real_user_check.o real_user_check.c

$(binFolder)create_files_umask: $(objectFolder)create_files_umask.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)create_files_umask $(objectFolder)create_files_umask.o -lapue

$(objectFolder)create_files_umask.o: create_files_umask.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)create_files_umask.o create_files_umask.c

$(binFolder)change_file_permissions: $(objectFolder)change_file_permissions.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)change_file_permissions $(objectFolder)change_file_permissions.o -lapue

$(objectFolder)change_file_permissions.o: change_file_permissions.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)change_file_permissions.o change_file_permissions.c

$(binFolder)unlink_tempfile: $(objectFolder)unlink_tempfile.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)unlink_tempfile $(objectFolder)unlink_tempfile.o -lapue

$(objectFolder)unlink_tempfile.o: unlink_tempfile.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)unlink_tempfile.o unlink_tempfile.c

$(binFolder)silent_change: $(objectFolder)silent_change.o
	echo "babababababababababababababababa" > $(binFolder)kk.txt
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)silent_change $(objectFolder)silent_change.o -lapue

$(objectFolder)silent_change.o: silent_change.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)silent_change.o silent_change.c

$(binFolder)path_traverser: $(objectFolder)path_traverser.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)path_traverser $(objectFolder)path_traverser.o -lapue

$(objectFolder)path_traverser.o: path_traverser.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)path_traverser.o path_traverser.c

$(binFolder)change_chdir: $(objectFolder)change_chdir.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)change_chdir $(objectFolder)change_chdir.o -lapue

$(objectFolder)change_chdir.o: change_chdir.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)change_chdir.o change_chdir.c

$(binFolder)get_current_dir: $(objectFolder)get_current_dir.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)get_current_dir $(objectFolder)get_current_dir.o -lapue

$(objectFolder)get_current_dir.o: get_current_dir.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)get_current_dir.o get_current_dir.c

#################################################################
# Clean but don't remove directories
#################################################################
clean:
	rm -rf $(objectFolder)*.o
	rm -rf $(binFolder)type_printer
	rm -rf $(binFolder)real_user_check
	rm -rf $(binFolder)create_files_umask
	rm -rf $(binFolder)change_file_permissions
	rm -rf $(binFolder)unlink_tempfile
	rm -rf $(binFolder)silent_change
	rm -rf $(binFolder)kk.txt
	rm -rf $(binFolder)path_traverser
	rm -rf $(binFolder)change_chdir
	rm -rf $(binFolder)get_current_dir
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
