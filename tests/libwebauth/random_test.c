#include <stdio.h>

#include "webauth.h"

#define BUFSIZE 2048

int main(int argc, char *argv[])
{
    unsigned char orig_buffer[BUFSIZE];
    unsigned char encoded_buffer[BUFSIZE];
    int s;
    int elen,errors;

    errors = 0;

    s = webauth_random_key(orig_buffer, WA_AES_128);

    printf("status = [%d]\n", s);

    elen = webauth_hex_encode(orig_buffer, WA_AES_128, 
                              encoded_buffer, BUFSIZE);

    encoded_buffer[elen] = '\0';

    printf("buffer = [%s]\n", encoded_buffer);

    s = webauth_random_bytes(orig_buffer, WA_AES_128);

    printf("status = [%d]\n", s);

    elen = webauth_hex_encode(orig_buffer, WA_AES_128, 
                              encoded_buffer, BUFSIZE);

    encoded_buffer[elen] = '\0';

    printf("buffer = [%s]\n", encoded_buffer);

    exit(errors > 0 ? 1 : 0);
}
