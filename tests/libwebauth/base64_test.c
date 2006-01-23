
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

#define BUFSIZE 1024

int main(int argc, char *argv[])
{
    char orig_buffer[BUFSIZE];
    char encoded_buffer[BUFSIZE];
    char decoded_buffer[BUFSIZE];
    int i,j;
    int elen, rlen, rdlen, dlen;
    int equal;
    int s;
    TEST_VARS;

    START_TESTS(3577);

    for (i=1; i < 512; i++) {
        for (j=0; j < i; j++) {
            orig_buffer[j] = j % 256;
        }
        s = webauth_base64_encode(orig_buffer, i,
                                  encoded_buffer, &elen, BUFSIZE);
        rlen = webauth_base64_encoded_length(i);
        TEST_OK(s == WA_ERR_NONE);
        TEST_OK(elen == rlen);

        s = webauth_base64_decoded_length(encoded_buffer, elen, &rdlen);
        TEST_OK(s == WA_ERR_NONE);

        s = webauth_base64_decode(encoded_buffer, elen, 
                                     decoded_buffer, &dlen, BUFSIZE);
        TEST_OK(s == WA_ERR_NONE);
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
