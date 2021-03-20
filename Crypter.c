#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include "aes.h"

int round_up(int toRound, int multiple) {
    if (multiple == 0)
        return toRound;

    int rem = toRound % multiple;
    if (rem == 0)
        return toRound;

    return toRound + multiple - rem;
}

int main(int argc, char * argv[]) {
    int fd = open("/usr/lib/os-release", O_RDONLY);
    const uint8_t key[16];
    int read_in  = read(fd, key, AES_KEYLEN);
    close(fd);


    uint8_t iv[] = "whatisthiscapt??"; 
    int input_size = atoi(argv[2]);

    // Allocate buffer for Stage2 Malloc
    int malloc_size = round_up(input_size, AES_KEYLEN);
    uint8_t * dec_buf = (uint8_t *) calloc(malloc_size, 1);

    // Read in compiled stage2    
    int s2_fd = open(argv[1], O_RDONLY);
    read_in = read(s2_fd, dec_buf, input_size); 

    close(s2_fd);
    
    struct AES_ctx context;
    AES_init_ctx_iv(&context, key, iv);

    if (dec_buf != NULL) {
        // Decrypt the buffer
        AES_CBC_encrypt_buffer(&context, dec_buf, malloc_size);

        // Open file for writing 
        int outfile = open("stage2", O_CREAT | O_WRONLY , 0755);
        if (outfile) {
            // Write the extern blob
            write(outfile, dec_buf, malloc_size);
            // Close
            close(outfile);
        }
            free(dec_buf);
    }
}
