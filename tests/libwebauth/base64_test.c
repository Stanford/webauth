#include <stdio.h>

#include "webauth.h"

#define BUFSIZE 1024

int main(int argc, char *argv[])
{
    unsigned char orig_buffer[BUFSIZE];
    unsigned char encoded_buffer[BUFSIZE];
    unsigned char decoded_buffer[BUFSIZE];
    int i,j;
    int elen, rlen, rdlen, dlen, errors;

    errors = 0;
    for (i=1; i < 512; i++) {
        for (j=0; j < i; j++) {
            orig_buffer[j] = j % 256;
        }
        elen = webauth_base64_encode(orig_buffer, i, encoded_buffer, BUFSIZE);
        rlen = webauth_base64_encoded_length(i);
        if (elen != rlen) {
            fprintf(stderr, "ERROR: elen(%d) != rlen(%d)\n", elen, rlen);
            errors++;
        }
        rdlen = webauth_base64_decoded_length(encoded_buffer, elen);
        dlen = webauth_base64_decode(encoded_buffer, elen, 
                                     decoded_buffer, BUFSIZE);

        if (dlen != rdlen) {
            fprintf(stderr, "ERROR: dlen(%d) != rdlen(%d)\n", dlen, rdlen);
            errors++;
        }

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
