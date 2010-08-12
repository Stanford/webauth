/*
 * Command-line utility for manipulating WebAuth keyrings.
 *
 * Written by Roland Schemers and Russ Allbery
 * Copyright 2002, 2003, 2006, 2009, 2010
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/stdbool.h>
#include <portable/system.h>

#include <assert.h>
#include <errno.h>
#include <openssl/md5.h>

#include <lib/webauth.h>
#include <util/messages.h>
#include <util/xmalloc.h>

/* Usage message. */
static const char usage_message[] = "\
Usage: %s [-hv] -f <keyring> list\n\
       %s -f <keyring> add <valid-after>\n\
       %s -f <keyring> gc <oldest-valid-after-to-keep>\n\
       %s -f <keyring> remove <id>\n\
\n\
Functions:\n\
  add <valid-after>                 # add a new random key\n\
  gc <oldest-valid-after-to-keep>   # garbage collect old keys\n\
  list                              # list keys\n\
  remove <id>                       # remove key by id\n\
\n\
<valid_after> and <oldest-valid-after-to-keep> use the format\n\
[-]<nnnn>[s|m|h|d|w], indicating a time relative to the current time.  The\n\
units for the time are specified by appending a single letter, which can\n\
be s, m, h, d, or w, corresponding to seconds minutes, hours, days, and\n\
weeks, respectively.  For example, 10d is 10 days from the current time,\n\
and -60d is 60 days before the current time.  Negative relative times are\n\
useful with gc.\n";


/*
 * Die with an error, appending a WebAuth error message.  Tries to follow the
 * interface and behavior of the messages library as closely as possible.
 */
static void
die_webauth(int s, const char *fmt, ...)
{
    va_list args;

    if (message_program_name != NULL)
        fprintf(stderr, "%s: ", message_program_name);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    if (s != 0)
        fprintf(stderr, ": %s", webauth_error_message(s));
    fprintf(stderr, "\n");
    exit(message_fatal_cleanup ? (*message_fatal_cleanup)() : 1);
}


/*
 * Display the usage message for remctl.
 */
static void
usage(int status)
{
    fprintf((status == 0) ? stdout : stderr, usage_message,
            message_program_name, message_program_name, message_program_name,
            message_program_name);
    exit(status);
}


/*
 * Convert a time value to seconds, supporting a single character for units.
 * s, m, h, d, and w are the supported units, representing seconds, minutes,
 * hours, days, and weeks respectively.
 */
static long
seconds(const char *value)
{
    long n;
    long multiplier = 0;
    char *end;

    assert(value != NULL);
    if (*value == '\0')
        die("invalid empty time value");

    switch (value[strlen(value) - 1]) {
    case 's':
        multiplier = 1;
        break;
    case 'm':
        multiplier = 60;
        break;
    case 'h':
        multiplier = 60 * 60;
        break;
    case 'd':
        multiplier = 60 * 60 * 24;
        break;
    case 'w':
        multiplier = 60 * 60 * 24 * 7;
        break;
    default:
        die("invalid time specification: %s", value);
        break;
    }

    errno = 0;
    n = strtol(value, &end, 10);
    if (errno != 0 || end != value + strlen(value) - 1)
        die("invalid time specification: %s", value);
    return n * multiplier;
}


/*
 * Given a time_t, print it to standard output in the local time zone using
 * the ISO date and time representation but without the time zone.
 */
static void
print_time(time_t t)
{
    struct tm *tm;
    char buf[128];

    tm = localtime(&t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
    printf("%s", buf);
}


/*
 * Given a WebAuth key, print a fingerprint of that key to standard output.
 * The fingerprint is the MD5 checksum of the key.  This is used to check
 * whether two keys are the same without exposing the actual key value.
 */
static void
print_fingerprint(WEBAUTH_KEY *key)
{
    char md5[MD5_DIGEST_LENGTH];
    char *hex;
    size_t length, maxlen;
    int s;
    MD5_CTX c;

    MD5_Init(&c);
    MD5_Update(&c, key->data, key->length);
    MD5_Final((unsigned char *) md5, &c);
    maxlen = webauth_hex_encoded_length(MD5_DIGEST_LENGTH);
    hex = xmalloc(maxlen + 1);
    s = webauth_hex_encode(md5, MD5_DIGEST_LENGTH, hex, &length, maxlen);
    if (s != WA_ERR_NONE)
        die_webauth(s, "cannot encode fingerprint of key");
    hex[length] = '\0';
    printf("%s", hex);
    free(hex);
}


/*
 * Given a keyring entry, print it in the short format.  Each entry will look
 * like:
 *
 *     0  2009-06-27 15:29:19  2009-06-27 15:29:19  <fingerprint>
 *
 * where the first column is the id, the next is the creation timestamp, the
 * third is the date at which the key becomes valid, and the last is the MD5
 * fingerprint of the key.  Takes the keyring entry and its index, which is
 * used as the key ID.
 */
static void
print_short(WEBAUTH_KEYRING_ENTRY *e, size_t i)
{
    printf("%2lu  ", (unsigned long) i);
    print_time(e->creation_time);
    printf("  ");
    print_time(e->valid_after);
    printf("  ");
    print_fingerprint(e->key);
    printf("\n");
}


/*
 * Given a keyring entry, print it in the long format.  Each entry will look
 * like:
 *
 *          Key-Id: 0
 *         Created: 2009-06-27 15:29:19
 *     Valid-After: 2009-06-27 15:29:19
 *        Key-Type: 1 (AES)
 *      Key-Length: 16 (128 bits)
 *     Fingerprint: 23e59c1d193113afc9d0257f42a64369
 *
 * Takes the keyring entry and its index, which is used as the key ID.
 */
static void
print_long(WEBAUTH_KEYRING_ENTRY *e, size_t i)
{
    printf("       Key-Id: %lu\n", (unsigned long) i);
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
    printf("   Key-Length: %lu bits\n", (unsigned long) e->key->length * 8);
    printf("  Fingerprint: ");
    print_fingerprint(e->key);
    printf("\n\n");
}


/*
 * List the entries in the keyring.  The default output format looks like:
 *
 *     Path: webauth_keyring
 *
 *     id  Created              Valid after          Fingerprint
 *      0  2009-06-27 15:29:19  2009-06-27 15:29:19  23e59c1d193113afc9...
 *
 * If the verbose flag is true, the output will instead look like:
 *
 *             Path: keyring
 *         Num-Keys: 1
 *
 *           Key-Id: 0
 *          Created: 2009-06-27 15:29:19
 *      Valid-After: 2009-06-27 15:29:19
 *         Key-Type: 1 (AES)
 *       Key-Length: 128 bits
 *      Fingerprint: 23e59c1d193113afc9d0257f42a64369
 *
 * Takes the path to the keyring and the verbose flag.
 */
static void
list_keyring(const char *keyring, bool verbose)
{
    WEBAUTH_KEYRING *ring;
    int s;
    size_t i;

    s = webauth_keyring_read_file(keyring, &ring);
    if (s != WA_ERR_NONE)
        die_webauth(s, "cannot read keyring %s", keyring);
    if (verbose) {
        printf("         Path: %s\n", keyring);
        printf("     Num-Keys: %lu\n\n", (unsigned long) ring->num_entries);
    } else {
        printf("Path: %s\n", keyring);
        printf("\n");
        printf("id  Created              Valid after          Fingerprint\n");
    }
    for (i = 0; i < ring->num_entries; i++)
        if (verbose)
            print_long(&ring->entries[i], i);
        else
            print_short(&ring->entries[i], i);
    webauth_keyring_free(ring);
}


/*
 * Add a new key to a keyring.  Takes the path to the keyring and the offset
 * in seconds at which the new key should become valid.
 */
static void
add_key(const char *keyring, long valid_after)
{
    WEBAUTH_KEY *key;
    WEBAUTH_KEYRING *ring;
    int s;
    time_t now;
    char key_material[WA_AES_128];

    s = webauth_keyring_read_file(keyring, &ring);
    if (s != WA_ERR_NONE)
        ring = webauth_keyring_new(32);
    s = webauth_random_key(key_material, WA_AES_128);
    if (s != WA_ERR_NONE)
        die_webauth(s, "cannot generate new random key");
    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    now = time(NULL);
    s = webauth_keyring_add(ring, now, now + valid_after, key);
    if (s != WA_ERR_NONE)
        die_webauth(s, "cannot add new key to the keyring");
    webauth_key_free(key);
    s = webauth_keyring_write_file(ring, keyring);
    if (s != WA_ERR_NONE)
        die_webauth(s, "cannot write keyring to %s", keyring);
    webauth_keyring_free(ring);
}


/*
 * Remove a key from a keyring.  Takes the index in the keyring of the key to
 * remove.
 */
static void
remove_key(const char *keyring, unsigned long index)
{
    WEBAUTH_KEYRING *ring;
    int s;

    s = webauth_keyring_read_file(keyring, &ring);
    if (s != WA_ERR_NONE)
        die_webauth(s, "cannot read keyring %s", keyring);
    s = webauth_keyring_remove(ring, index);
    if (s != WA_ERR_NONE)
        die_webauth(s, "cannot remove key %lu from keyring", index);
    s = webauth_keyring_write_file(ring, keyring);
    if (s != WA_ERR_NONE)
        die_webauth(s, "cannot write keyring to %s", keyring);
    webauth_keyring_free(ring);
}


/*
 * Garbage-collect the keys in the keyring.  Any key whose valid-after date is
 * older than the current time adjusted by the offset passed in to gc_keys is
 * removed from the keyring.
 */
static void
gc_keys(const char *keyring, long offset)
{
    WEBAUTH_KEYRING *ring;
    int s;
    bool removed;
    size_t i;
    time_t now, earliest;

    s = webauth_keyring_read_file(keyring, &ring);
    if (s != WA_ERR_NONE)
        die_webauth(s, "cannot read keyring %s", keyring);
    now = time(NULL);
    earliest = now + offset;
    do {
        removed = false;
        for (i = 0; i < ring->num_entries; i++)
            if (ring->entries[i].valid_after < earliest) {
                s = webauth_keyring_remove(ring, i);
                if (s != WA_ERR_NONE)
                    die_webauth(s, "cannot remove key %lu from keyring", i);
                removed = true;
            }
    } while (removed);
    s = webauth_keyring_write_file(ring, keyring);
    if (s != WA_ERR_NONE)
        die_webauth(s, "cannot write keyring to %s", keyring);
    webauth_keyring_free(ring);
}


int
main(int argc, char **argv)
{
    int option;
    bool verbose = false;
    unsigned long id;
    long offset;
    char *end;
    const char *keyring = NULL;
    const char *command = "list";

    message_program_name = argv[0];

    /*
     * The + tells GNU getopt to stop option parsing at the first non-argument
     * rather than proceeding on to find options anywhere.  This allows easier
     * specification of negative time offsets.
     */
    while ((option = getopt(argc, argv, "+f:hv")) != EOF) {
        switch (option) {
        case 'f':
            keyring = optarg;
            break;
        case 'h':
            usage(0);
            break;
        case 'v':
            verbose = true;
            break;
        case '+':
            fprintf(stderr, "%s: invalid option -- +\n", argv[0]);
        default:
            usage(1);
            break;
        }
    }
    argc -= optind;
    argv += optind;
    if (keyring == NULL || argc > 2)
        usage(1);
    if (argc > 0) {
        command = argv[0];
        argc--;
        argv++;
    }

    if (strcmp(command, "list") == 0) {
        if (argc > 0)
            usage(1);
        list_keyring(keyring, verbose);
    } else if (strcmp(command, "add") == 0) {
        if (argc != 1)
            usage(1);
        offset = seconds(argv[0]);
        add_key(keyring, offset);
    } else if (strcmp(command, "gc") == 0) {
        if (argc != 1)
            usage(1);
        offset = seconds(argv[0]);
        gc_keys(keyring, offset);
    } else if (strcmp(command, "remove") == 0) {
        if (argc != 1)
            usage(1);
        errno = 0;
        id = strtoul(argv[0], &end, 10);
        if (errno != 0 || *end != '\0')
            die("invalid key id: %s", argv[0]);
        remove_key(keyring, id);
    } else {
        usage(1);
    }
    exit(0);
}
