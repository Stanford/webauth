/*
 * Command-line utility for manipulating WebAuth keyrings.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2006, 2009
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include "config.h"

#include <stdio.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

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
    fprintf(stderr, "  add {valid_after}                 # add a new key\n");
    fprintf(stderr, "  gc {oldest-valid-after-to-keep}   # garbage collect\n");
    fprintf(stderr, "  list                              # list keys\n");
    fprintf(stderr, "  remove {id}                       # remove key by id\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "valid_after/oldest-valid-after-to-keep use the format: nnnn[s|m|h|d|w]\n");
    fprintf(stderr, "which indicates a time relative to the current time. The units for the time\n");
    fprintf(stderr, "are specified by appending a single letter, which can either be s, m, h, d,\n");
    fprintf(stderr, "or w, which correspond to seconds, minutes, hours, days, and weeks\n");
    fprintf(stderr, "respectively. For example: 10d is 10 days from the current time,\n");
    fprintf(stderr, "and -60d is 60 days before the current time (negative realative times\n");
    fprintf(stderr, "are useful with gc).\n");
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
  prog = argv[0];

  while (--argc && *++argv && argv[0][0] == '-') {
      switch (argv[0][1]) {
          case 'h':
              usage(0);
              break;
          case  'v':
              verbose = 1;
              break;
          case 'f':
              keyring_path = *++argv;
              break;
          default:
              usage(1);
              break;
      }
  }

  if (keyring_path == NULL || argv == NULL) {
      usage(1);
  }

  return argv;
}

void
print_time(time_t t)
{
    struct tm *tm;
    char buff[128];
    tm = localtime(&t);
    strftime(buff, sizeof(buff), "%m/%d/%Y %H:%M:%S", tm);
    printf("%s", buff);
}

void
get_fingerprint(WEBAUTH_KEY *key, char *hex, int hex_len)
{
    unsigned char md5[MD5_DIGEST_LENGTH]; 
    int len, s;

    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, key->data, key->length);
    MD5_Final(md5, &c);
 
    s = webauth_hex_encode((char *) md5, MD5_DIGEST_LENGTH, hex, &len,
                           hex_len);
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
    print_time(e->creation_time);
    printf("  ");
    print_time(e->valid_after);
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
    printf("  Valid-After: ");
    print_time(e->valid_after);
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

  Created           Valid after        Fingerprint
  10/16/02 12:25:11 10/16/02 22:25:11  85e6 d033 0f87 b1d9 89b7 4fe2 a239 f990
  ------------------------------------------------------------

  verbose:

  ------------------------------------------------------------
         Path: webauth_keyring
      Version: 1
         Keys: 1

       Key-Id: 0
      Created: 10/16/02 12:25:03
  Valid-After: 10/16/02 12:25:03
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
        printf("id  Created              Valid after          Fingerprint\n");
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

void add_key(char *valid_after)
{
    WEBAUTH_KEY *key;
    WEBAUTH_KEYRING *ring;
    int s;
    char key_material[WA_AES_128];
    time_t curr, vf;
    
    s = webauth_keyring_read_file(keyring_path, &ring);
    if (s != WA_ERR_NONE) {
        ring = webauth_keyring_new(32);
    }
    
    s = webauth_random_key(key_material, WA_AES_128);
    if (s != WA_ERR_NONE)
        croak(s);

    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);

    time(&curr);

    vf = seconds(valid_after);

    s = webauth_keyring_add(ring, curr, curr+vf, key);
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


void gc_keys(char *oldest_valid_after)
{
    WEBAUTH_KEYRING *ring;
    int s, i, removed;
    time_t curr, ovf;

    s = webauth_keyring_read_file(keyring_path, &ring);
    if (s != WA_ERR_NONE) {
        croak(s);
    }

    time(&curr);
    ovf = curr+seconds(oldest_valid_after);

    do {
        removed = 0;
        for (i=0; i < ring->num_entries; i++) {
            if (ring->entries[i].valid_after < ovf) {
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
        char *valid_after;
        if (!*argv) usage(1);
        valid_after = *argv++;
        if (*argv) usage(1);
        add_key(valid_after);
    } else if (strcmp(cmd, "gc") == 0) {
        char *oldest_valid_after;
        if (!*argv) usage(1);
        oldest_valid_after = *argv++;
        if (*argv) usage(1);
        gc_keys(oldest_valid_after);
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
