#include <stdio.h>

#include "webauth.h"

#define BUFSIZE 2048

int main(int argc, char *argv[])
{
    unsigned char orig_buffer[BUFSIZE];
    unsigned char encoded_buffer[BUFSIZE];
    unsigned char decoded_buffer[BUFSIZE];
    int i,j;
    int elen, rlen, dlen, errors;

    errors = 0;
    for (i=0; i < 512; i++) {
        for (j=0; j < i; j++) {
            orig_buffer[j] = j % 256;
        }
        elen = webauth_hex_encode(orig_buffer, i, encoded_buffer, BUFSIZE);
        rlen = webauth_hex_encoded_length(i);
        if (elen != rlen) {
            fprintf(stderr, "ERROR: elen(%d) != rlen(%d)\n", elen, rlen);
            errors++;
        }

        dlen = webauth_hex_decode(encoded_buffer, elen, 
                                  decoded_buffer, BUFSIZE);
        if (dlen != i) {
            fprintf(stderr, "ERROR: dlen(%d) != i(%d)\n", dlen, i);
            errors++;
        }
        for (j=0; j < i; j++) {
            if (decoded_buffer[j] != orig_buffer[j]) {
                fprintf(stderr, "ERROR: decoded buffer compare: i(%d) j(%d)\n",
                        i, j);
                errors++;
            }
        }
    }
    exit(errors > 0 ? 1 : 0);
}
