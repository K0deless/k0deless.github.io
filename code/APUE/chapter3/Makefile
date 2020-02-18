CC=gcc -g3 -Wall
libDir=/home/Fare9/Documents/APUE/apue.3e/lib/
includeDir=/home/Fare9/Documents/APUE/apue.3e/include/
objectFolder=./objF9/
binFolder=./binF9/
MKDIR_P=mkdir -p

.PHONY: directories clean remove

all: directories $(binFolder)test_lseek $(binFolder)file_hole $(binFolder)copy_file \
	$(binFolder)check_file_descriptor_flags

$(binFolder)check_file_descriptor_flags: $(objectFolder)check_file_descriptor_flags.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)check_file_descriptor_flags $(objectFolder)check_file_descriptor_flags.o -lapue

$(objectFolder)check_file_descriptor_flags.o: check_file_descriptor_flags.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)check_file_descriptor_flags.o check_file_descriptor_flags.c

$(binFolder)test_lseek: $(objectFolder)test_lseek.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)test_lseek $(objectFolder)test_lseek.o -lapue

$(objectFolder)test_lseek.o: test_lseek.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)test_lseek.o test_lseek.c

$(binFolder)file_hole: $(objectFolder)file_hole.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)file_hole $(objectFolder)file_hole.o -lapue

$(objectFolder)file_hole.o: file_hole.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)file_hole.o file_hole.c

$(binFolder)copy_file: $(objectFolder)copy_file.o
	$(CC) -I $(includeDir) -L $(libDir) -o $(binFolder)copy_file $(objectFolder)copy_file.o -lapue

$(objectFolder)copy_file.o: copy_file.c
	$(CC) -I $(includeDir) -c -o $(objectFolder)copy_file.o copy_file.c

#################################################################
# Clean but don't remove directories
#################################################################
clean:
	rm -rf $(objectFolder)*.o
	rm -rf $(binFolder)test_lseek
	rm -rf $(binFolder)file_hole
	rm -rf $(binFolder)copy_file
	rm -rf $(binFolder)check_file_descriptor_flags

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
