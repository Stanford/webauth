#include <stdlib.h>
#include <stdio.h>

#include "webauth.h"

#define BUFSIZE 4096
#define MAX_ATTRS 128

/*
 * FIXME: this will eventually be the tool that 
 * creates keyring files and keeps them up to date.
 * more of a test program right now (and a bad one at that)
 *
 */


static void usage(char *prog)
{
    printf("usage: %s -f keyring [options]\n", prog);
    printf("  -f <keyring file>   keyring file to use\n");
    printf("  -h                  help\n");
    printf("  -l                  list keyring file\n");
    printf("  -v                  verbose\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    WEBAUTH_KEY *key;
    WEBAUTH_KEYRING *ring;

    int s,i ;
    unsigned char key_material[WA_AES_128];
    unsigned char hex[2048];
    time_t curr;

    /*


default:

------------------------------------------------------------
Path: webauth_keyring

Valid from      Valid till      Fingerprint
10/16/02 12:25  10/16/02 22:25  85E6 D033 0F87 B1D9 89B7 4FE2 A239 F990
------------------------------------------------------------

verbose:

------------------------------------------------------------
       Path: webauth_keyring
    Version: 1
       Keys: 1

  Key-Index: 0
    Created: 10/16/02 12:25:03
 Valid-From: 10/16/02 12:25:03
 Valid-Till: 10/17/02 12:25:03
   Key-Type: 1 (AES)
 Key-Length: 16 (128 bits)
Fingerprint: 85E6 D033 0F87 B1D9 89B7 4FE2 A239 F990

------------------------------------------------------------



     */
    if (argc>1) {
        s = webauth_keyring_read_file("webauth_keyring", &ring);
        for (i=0; i < ring->num_entries; i++) {

        }
    } else {
        ring = webauth_keyring_new(32);
        s = webauth_random_key(key_material, WA_AES_128);
        s=webauth_hex_encode(key_material, WA_AES_128, hex, sizeof(hex));
        hex[s] = '\0';
        /*printf("key[%s]\n", hex);*/

        key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
        time(&curr);
        s = webauth_keyring_add(ring, curr, curr, curr+3600, key);

        s = webauth_random_key(key_material, WA_AES_128);
        s=webauth_hex_encode(key_material, WA_AES_128, hex, sizeof(hex));
        hex[s] = '\0';
        /*printf("key[%s]\n", hex);*/

        key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
        s = webauth_keyring_add(ring, curr, curr+3600, curr+7200, key);
        s = webauth_keyring_write_file(ring,"webauth_keyring");
    }
    webauth_keyring_free(ring);

    exit(0);
}
