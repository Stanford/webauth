#include <stdlib.h>
#include <stdio.h>

#include "webauth.h"
#include "webauthtest.h"

#define BUFSIZE 4096
#define MAX_ATTRS 128

int main(int argc, char *argv[])
{
    WEBAUTH_KEY *key;
    WEBAUTH_KEY_RING *ring;
    int s;
    unsigned char key_material[WA_AES_128];
    unsigned char hex[2048];
    time_t curr;
    TEST_VARS;

    START_TESTS(3);

    s = webauth_random_key(key_material, WA_AES_128);
    TEST_OK2(WA_ERR_NONE, s);

    s=webauth_hex_encode(key_material, WA_AES_128, hex, sizeof(hex));
    hex[s] = '\0';
    /*printf("key[%s]\n", hex);*/


    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    TEST_OK(key != NULL);

    ring = webauth_key_ring_new(32);

    time(&curr);
    s = webauth_key_ring_add(ring, curr, curr, curr, key);
    TEST_OK2(WA_ERR_NONE, s);

    webauth_key_ring_free(ring);

    END_TESTS;
    exit(NUM_FAILED_TESTS ? 1 : 0);
}
