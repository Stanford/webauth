#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <openssl/md5.h>

#include "webauth.h"

#define BUFSIZE 4096
#define MAX_ATTRS 128

/*
 * FIXME: this will eventually be the tool that 
 * creates keyring files and keeps them up to date.
 * right now it just creates two keys and lists the keys in the ring.
 *
 */


/*
 * GLOBALS
 */
static char *prog = "wa_keyring";
static int verbose = 0;
static char *keyring_path = NULL;

static void croak(int s)
{
    fprintf(stderr, "%s: error code %d: %s\n", prog, s, webauth_error_message(s));
    exit(1);
}

static void usage(int exitcode)
{
    fprintf(stderr, "usage: %s -f keyring [list|create]\n", prog);
    fprintf(stderr, "  -f <keyring file>   keyring file to use\n");
    fprintf(stderr, "  -h                  help\n");
    fprintf(stderr, "  -v                  verbose listing\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  list (default) lists the keys in the ring\n");
    fprintf(stderr, "  create will create two keys in the key ring\n");
    exit(exitcode);
}

char **
read_options(int argc, char **argv)
{
  int c;
  extern int opterr;
  opterr = 0;

  prog = argv[0];

  /* A quick hack to honor --help and --version */
  if (argv[1])
    if (argv[1][0] == '-' && argv[1][1] == '-' && argv[1][2] != '\0') {
      switch(argv[1][2]) {
      case 'h':
	usage(0);
	break;
      default:
	usage(1);
	break;
      }
    }
 
  while ((c = getopt(argc, argv, "hvf:")) != EOF) {
      switch (c) {
          case 'f': /* keyring File */
              keyring_path = optarg;
              break;
          case 'h': /* Help */
              usage(0);
              break;
          case 'v':
              verbose=1;
              break;
          default:
              usage(1);
              break;
      }
  }

  if (keyring_path == NULL || optind > argc) {
      usage(1);
  }

  return argv+optind;
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

void list_keyring()
{
    WEBAUTH_KEYRING *ring;
    int s, i;
    
    s = webauth_keyring_read_file(keyring_path, &ring);
    if (s != WA_ERR_NONE)
        croak(s);

    if (verbose) {
        printf("         Path: %s\n", keyring_path);
        printf("     Num-Keys: %d\n\n", ring->num_entries);
    } else {
        printf("Path: %s\n", keyring_path);
        printf("\n");
        printf("Valid from         Valid till         Fingerprint\n");
    }

    for (i=0; i < ring->num_entries; i++) {
        if (verbose) {
            print_long(&ring->entries[i], i);
        } else {
            print_short(&ring->entries[i]);
        }
    }
    webauth_keyring_free(ring);
}

void create_keyring()
{
    WEBAUTH_KEY *key;
    WEBAUTH_KEYRING *ring;
    int s;
    unsigned char key_material[WA_AES_128];
    time_t curr;
     
    ring = webauth_keyring_new(32);
    s = webauth_random_key(key_material, WA_AES_128);
    if (s != WA_ERR_NONE)
        croak(s);
    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    time(&curr);
    s = webauth_keyring_add(ring, curr, curr, curr+3600*24*30, key);
    if (s != WA_ERR_NONE)
        croak(s);

    s = webauth_random_key(key_material, WA_AES_128);
    if (s != WA_ERR_NONE)
        croak(s);

    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    s = webauth_keyring_add(ring, curr, 
                            curr+1+3600*24*30, curr+1+3600*24*30*2, key);
    if (s != WA_ERR_NONE)
        croak(s);

    s = webauth_keyring_write_file(ring, keyring_path);
    if (s != WA_ERR_NONE)
        croak(s);

    webauth_keyring_free(ring);
}

int main(int argc, char **argv)
{
    char *cmd = NULL;

    argv = read_options(argc, argv);

    if (!*argv) {
        cmd = "list";
    } else {
        cmd = *argv++;
    }

    if (*argv) {
        usage(1);
    }

    if (strcmp(cmd, "list") == 0) {
        list_keyring();
    } else if (strcmp(cmd, "create") == 0) {
        create_keyring();
    } else {
        usage(1);
    }
    exit(0);
}
