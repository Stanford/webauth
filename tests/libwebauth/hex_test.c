#include <stdio.h>

#include "webauth.h"
#include "webauthtest.h"

#define BUFSIZE 2048

int main(int argc, char *argv[])
{
    unsigned char orig_buffer[BUFSIZE];
    unsigned char encoded_buffer[BUFSIZE];
    unsigned char decoded_buffer[BUFSIZE];
    int i,j;
    int elen, rlen, dlen, equal;
    TEST_VARS;

    START_TESTS(2048);

    for (i=0; i < 512; i++) {
        for (j=0; j < i; j++) {
            orig_buffer[j] = j % 256;
        }
        elen = webauth_hex_encode(orig_buffer, i, encoded_buffer, BUFSIZE);
        rlen = webauth_hex_encoded_length(i);
        TEST_OK(elen == rlen);

        dlen = webauth_hex_decode(encoded_buffer, elen, 
                                  decoded_buffer, BUFSIZE);

        TEST_OK(dlen == webauth_hex_decoded_length(elen));
        TEST_OK(dlen == i);

        equal=1;
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
