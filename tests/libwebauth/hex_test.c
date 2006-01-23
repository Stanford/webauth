
#include "config.h"

#include <stdio.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "webauth.h"
#include "webauthtest.h"

#define BUFSIZE 2048

int main(int argc, char *argv[])
{
    char orig_buffer[BUFSIZE];
    char encoded_buffer[BUFSIZE];
    char decoded_buffer[BUFSIZE];
    int i,j, s;
    int elen, rlen, dlen, equal, dlen2;
    TEST_VARS;

    START_TESTS(3584);

    for (i=0; i < 512; i++) {
        for (j=0; j < i; j++) {
            orig_buffer[j] = j % 256;
        }
        s = webauth_hex_encode(orig_buffer, i, encoded_buffer, &elen, BUFSIZE);
        rlen = webauth_hex_encoded_length(i);
        TEST_OK2(WA_ERR_NONE, s);
        TEST_OK(elen == rlen);

        s = webauth_hex_decode(encoded_buffer, elen, 
                                  decoded_buffer, &dlen, BUFSIZE);
        TEST_OK2(WA_ERR_NONE, s);
        s = webauth_hex_decoded_length(elen, &dlen2);
        TEST_OK2(WA_ERR_NONE, s);
        TEST_OK(dlen == dlen2);
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
