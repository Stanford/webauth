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
    fprintf(stderr, "\n");
    fprintf(stderr, "usage: %s -f {keyring} [add|list|remove] ...\n", prog);
    fprintf(stderr, "  -f {keyring} keyring file to use\n");
    fprintf(stderr, "  -h           help\n");
    fprintf(stderr, "  -v           verbose listing\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  add {valid_from} {valid_till}     # add a new key\n");
    fprintf(stderr, "  gc {oldest-valid-till-to-keep}    # garbage collect\n");
    fprintf(stderr, "  list                              # list keys\n");
    fprintf(stderr, "  remove {id}                       # remove key by id\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "valid_from/valid_till/expired_since use the format: nnnn[s|m|h|d|w]\n");
    fprintf(stderr, "which indicates a time relative to the current time. The units for the time\n");
    fprintf(stderr, "are specified by appending a single letter, which can either be s, m, h, d,\n");
    fprintf(stderr, "or w, which correspond to seconds, minutes, hours, days, and weeks\n");
    fprintf(stderr, "respectively. For example: 10d is 10 days from the current time,\n");
    fprintf(stderr, "and -60d is 60 days before the current time (negative realative times\n");
    fprintf(stderr, "are useful with gc).\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples: (these will get moved to man page)\n");
    fprintf(stderr, " # add a key to the keyring valid from now, expiring in 60 days\n");
    fprintf(stderr, " %s -f keyring add 0d 60d\n", prog);
    fprintf(stderr, " # add a key to the keyring valid three days from now, expiring in 63 days\n");
    fprintf(stderr, " %s -f keyring add 3d 63d\n", prog);
    fprintf(stderr, " # remove keys from key ring that have expired more then 60 days ago\n");
    fprintf(stderr, " %s -f keyring gc -60d\n", prog);
    fprintf(stderr, " # remove key first key in the key ring\n");
    fprintf(stderr, " %s -f keyring remove 0\n", prog);
    fprintf(stderr, "\n");
    exit(exitcode);
}

static int
seconds(const char *value)
{
    char temp[32];
    int mult=0, len;
    
    len = strlen(value);
    if (len > (sizeof(temp)-1)) {
        fprintf(stderr, "error: invalid units specified: %s", value);
        usage(1);
    }

    strcpy(temp, value);

    switch(temp[len-1]) {
        case 's': 
            mult = 1;
            break;
        case 'm':
            mult = 60;
            break;
        case 'h': 
            mult = 60*60; 
            break;
        case 'd': 
            mult = 60*60*24; 
            break;
        case 'w': 
            mult = 60*60*24*7; 
            break;
        default:
            fprintf(stderr, "error: invalid units specified: %s", value);
            usage(1);
            break;
    }
    
    temp[len-1] = '\0';
    return atoi(temp) * mult;
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
get_fingerprint(WEBAUTH_KEY *key, char *hex, int hex_len)
{
    char md5[MD5_DIGEST_LENGTH]; 
    int len, s;
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, key->data, key->length);
    MD5_Final(md5, &c);
 
    s = webauth_hex_encode(md5, MD5_DIGEST_LENGTH, hex, &len, hex_len);
    hex[len] = '\0';
}

void
print_fingerprint(WEBAUTH_KEY *key)
{
    char hex[MD5_DIGEST_LENGTH*2+1];
    get_fingerprint(key, hex, sizeof(hex));
    printf("%s", hex);
}

void
print_short(WEBAUTH_KEYRING_ENTRY *e, int i)
{
    printf("%2d  ", i);
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
    printf("       Key-Id: %d\n", i);
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

       Key-Id: 0
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
        printf("id  Valid from         Valid till         Fingerprint\n");
    }

    for (i=0; i < ring->num_entries; i++) {
        if (verbose) {
            print_long(&ring->entries[i], i);
        } else {
            print_short(&ring->entries[i], i);
        }
    }
    webauth_keyring_free(ring);
}

void add_key(char *valid_from, char *valid_till)
{
    WEBAUTH_KEY *key;
    WEBAUTH_KEYRING *ring;
    int s;
    unsigned char key_material[WA_AES_128];
    time_t curr, vf, vt;
    
    s = webauth_keyring_read_file(keyring_path, &ring);
    if (s != WA_ERR_NONE) {
        ring = webauth_keyring_new(32);
    }
    
    s = webauth_random_key(key_material, WA_AES_128);
    if (s != WA_ERR_NONE)
        croak(s);

    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);

    time(&curr);

    vf = seconds(valid_from);
    vt = seconds(valid_till);

    s = webauth_keyring_add(ring, curr, curr+vf, curr+vt, key);
    if (s != WA_ERR_NONE)
        croak(s);

    webauth_key_free(key);

    s = webauth_keyring_write_file(ring, keyring_path);
    if (s != WA_ERR_NONE)
        croak(s);

    webauth_keyring_free(ring);
}

void remove_key(int index)
{
    WEBAUTH_KEYRING *ring;
    int s;
    
    s = webauth_keyring_read_file(keyring_path, &ring);
    if (s != WA_ERR_NONE) {
        croak(s);
    }

    s = webauth_keyring_remove(ring, index);
    if (s != WA_ERR_NONE) {
        croak(s);
    }

    s = webauth_keyring_write_file(ring, keyring_path);
    if (s != WA_ERR_NONE)
        croak(s);

    webauth_keyring_free(ring);
}


void gc_keys(char *oldest_valid_till)
{
    WEBAUTH_KEYRING *ring;
    int s, i, removed;
    time_t curr, ovt;

    s = webauth_keyring_read_file(keyring_path, &ring);
    if (s != WA_ERR_NONE) {
        croak(s);
    }

    time(&curr);
    ovt = curr+seconds(oldest_valid_till);

    do {
        removed = 0;
        for (i=0; i < ring->num_entries; i++) {
            if (ring->entries[i].valid_till < ovt) {
                s = webauth_keyring_remove(ring, i);
                if (s != WA_ERR_NONE) {
                    croak(s);
                }
                removed = 1;
            }
        }
    } while (removed);

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

    if (strcmp(cmd, "list") == 0) {
        if (*argv) usage(1);
        list_keyring();
    } else if (strcmp(cmd, "add") == 0) {
        char *valid_from, *valid_till;
        if (!*argv) usage(1);
        valid_from = *argv++;
        if (!*argv) usage(1);
        valid_till = *argv++;
        if (*argv) usage(1);
        add_key(valid_from, valid_till);
    } else if (strcmp(cmd, "gc") == 0) {
        char *oldest_valid_till;
        if (!*argv) usage(1);
        oldest_valid_till = *argv++;
        if (*argv) usage(1);
        gc_keys(oldest_valid_till);
    } else if (strcmp(cmd, "remove") == 0) {
        int id;
        if (!*argv) usage(1);
        id = atoi(*argv++);
        if (*argv) usage(1);
        remove_key(id);
    } else {
        usage(1);
    }
    exit(0);
}
