#include <stdlib.h>
#include <stdio.h>
#include <openssl/md5.h>

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


void
print_time(time_t t)
{
    struct tm *tm;
    char buff[128];
    tm = localtime(&t);
    strftime(buff, sizeof(buff), "%D %T", tm);
    printf("%s", buff);
}

void
print_fingerprint(WEBAUTH_KEY *key)
{
    char md5[MD5_DIGEST_LENGTH]; 
    char hex[MD5_DIGEST_LENGTH*2+1];
    int len, s;
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, key->data, key->length);
    MD5_Final(md5, &c);
 

    s = webauth_hex_encode(md5, MD5_DIGEST_LENGTH, hex, &len, sizeof(hex));
    hex[len] = '\0';
    printf("%s", hex);
}

void
print_short(WEBAUTH_KEYRING_ENTRY *e)
{
    print_time(e->valid_from);
    printf("  ");
    print_time(e->valid_till);
    printf("  ");
    print_fingerprint(e->key);
    printf("\n");
}


void
print_long(WEBAUTH_KEYRING_ENTRY *e, int i)
{
    printf("    Key-Index: %d\n", i);
    printf("      Created: ");
    print_time(e->creation_time);
    printf("\n");
    printf("   Valid-From: ");
    print_time(e->valid_from);
    printf("\n");
    printf("   Valid-Till: ");
    print_time(e->valid_till);
    printf("\n");
    printf("     Key-Type: %d (", e->key->type);
    switch (e->key->type) {
        case WA_AES_KEY:
            printf("AES");
            break;
        default:
            printf("UNKNOWN");
            break;
    }
    printf(")\n");
    printf("   Key-Length: %d (%d bits)\n",
           e->key->length, e->key->length*8);
    printf("  Fingerprint: ");
    print_fingerprint(e->key);
    printf("\n\n");
}

int main(int argc, char *argv[])
{
    WEBAUTH_KEY *key;
    WEBAUTH_KEYRING *ring;

    char *path = "webauth_keyring";
    int s,i ;
    unsigned char key_material[WA_AES_128];
     time_t curr;

    /*
default:

------------------------------------------------------------
Path: webauth_keyring

Valid from      Valid till      Fingerprint
10/16/02 12:25:11 10/16/02 22:25:11  85e6 d033 0f87 b1d9 89b7 4fe2 a239 f990
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
    if (argc<2) {
        s = webauth_keyring_read_file(path, &ring);
        printf("Path: %s\n", path);
        printf("Num-Keys: %d\n\n", ring->num_entries);
        printf("Valid from         Valid till         Fingerprint\n");
        if (ring->num_entries>0) {
            
        }
        for (i=0; i < ring->num_entries; i++) {
            //      print_short(&ring->entries[i]);
            print_long(&ring->entries[i], i);
        }


    } else {
        char hex[2048];
        int l;
        ring = webauth_keyring_new(32);
        s = webauth_random_key(key_material, WA_AES_128);
        s=webauth_hex_encode(key_material, WA_AES_128, hex, &l, sizeof(hex));
        hex[l] = '\0';
        /*printf("key[%s]\n", hex);*/

        key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
        time(&curr);
        s = webauth_keyring_add(ring, curr, curr, curr+3600*24*30, key);

        s = webauth_random_key(key_material, WA_AES_128);
        s = webauth_hex_encode(key_material, WA_AES_128, hex, &l, sizeof(hex));
        hex[l] = '\0';
        /*printf("key[%s]\n", hex);*/

        key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
        s = webauth_keyring_add(ring, curr, curr+1+3600*24*30, curr+1+3600*24*30*2, key);
        s = webauth_keyring_write_file(ring,"webauth_keyring");
    }
    webauth_keyring_free(ring);

    exit(0);
}
