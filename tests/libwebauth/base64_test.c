#include <stdio.h>

#include "webauth.h"
#include "webauthtest.h"

#define BUFSIZE 1024

int main(int argc, char *argv[])
{
    unsigned char orig_buffer[BUFSIZE];
    unsigned char encoded_buffer[BUFSIZE];
    unsigned char decoded_buffer[BUFSIZE];
    int i,j;
    int elen, rlen, rdlen, dlen;
    int equal;
    TEST_VARS;

    START_TESTS(2044);

    for (i=1; i < 512; i++) {
        for (j=0; j < i; j++) {
            orig_buffer[j] = j % 256;
        }
        elen = webauth_base64_encode(orig_buffer, i, encoded_buffer, BUFSIZE);
        rlen = webauth_base64_encoded_length(i);
        TEST_OK(elen == rlen);

        rdlen = webauth_base64_decoded_length(encoded_buffer, elen);
        dlen = webauth_base64_decode(encoded_buffer, elen, 
                                     decoded_buffer, BUFSIZE);

        TEST_OK(dlen == rdlen);
        TEST_OK(dlen == i);

        equal = 1;
        for (j=0; j < i; j++) {
            if (decoded_buffer[j] != orig_buffer[j]) {
                equal=0;
                break;
            }
        }
        TEST_OK(equal);
    }

    END_TESTS;
    exit(NUM_FAILED_TESTS ? 1 : 0);
}
