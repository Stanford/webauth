/*
 * Handling of keys and keyrings.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2004, 2005, 2006, 2009, 2010, 2012
 *    The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#include <lib/internal.h>
#include <webauth.h>
#include <webauth/basic.h>
#include <webauth/keys.h>

/* The version of the keyring file format that we implement. */
#define KEYRING_VERSION 1

/*
 * A keyring file as implemented in this code is a bunch of attributes.  Here
 * are the attributes and the types of their values:
 *
 *     v={version}           uint32_t
 *     n={num-entries}       uint32_t
 *     ct%d={creation-time}  time_t
 *     vf%d={valid-after}    time_t
 *     kt%d={key-type}       uint32_t
 *     key%d={key-data}      binary-data
 *
 * The attribute names containing %d repeat for each entry, starting with zero
 * for the first key.
 */
#define A_VERSION       "v"
#define A_NUM_ENTRIES   "n"
#define A_CREATION_TIME "ct%lu"
#define A_VALID_AFTER   "va%lu"
#define A_KEY_TYPE      "kt%lu"
#define A_KEY_DATA      "kd%lu"


/*
 * Create a new keyring.  Takes one argument specifying the initial capacity
 * of the keyring.  Returns the newly allocated structure.
 */
struct webauth_keyring *
webauth_keyring_new(struct webauth_context *ctx, size_t capacity)
{
    struct webauth_keyring *ring;
    size_t size = sizeof(struct webauth_keyring_entry);

    if (capacity < 1)
        capacity = 1;
    ring = apr_palloc(ctx->pool, sizeof(struct webauth_keyring));
    ring->entries = apr_array_make(ctx->pool, capacity, size);
    return ring;
}


/*
 * Add a key to a keyring.  Takes the ring, the creation time, the time at
 * which the key becomes valid, and the key.  Either of the times may be zero,
 * in which case the current time is used.  Makes a copy of the key when
 * inserting it.
 */
void
webauth_keyring_add(struct webauth_context *ctx, struct webauth_keyring *ring,
                    time_t creation, time_t valid_after,
                    const struct webauth_key *key)
{
    struct webauth_keyring_entry entry;

    entry.creation = creation;
    entry.valid_after = valid_after;
    entry.key = webauth_key_copy(ctx, key);
    APR_ARRAY_PUSH(ring->entries, struct webauth_keyring_entry) = entry;
}


/*
 * Given a key, wrap a keyring around it.  The keyring and its data structures
 * are allocated from the pool.
 */
struct webauth_keyring *
webauth_keyring_from_key(struct webauth_context *ctx,
                         const struct webauth_key *key)
{
    struct webauth_keyring *ring;

    ring = webauth_keyring_new(ctx, 1);
    webauth_keyring_add(ctx, ring, 0, 0, key);
    return ring;
}


/*
 * Remove a key from a keyring by index and shifts the other keys down.
 * Returns WA_ERR_NOT_FOUND if the index is outside the bounds of the array.
 */
int
webauth_keyring_remove(struct webauth_context *ctx,
                       struct webauth_keyring *ring, size_t n)
{
    size_t i;
    apr_array_header_t *entries = ring->entries;
    struct webauth_keyring_entry *entry;

    if (n > (size_t) entries->nelts) {
        webauth_error_set(ctx, WA_ERR_NOT_FOUND,
                          "keyring index %lu out of range",
                          (unsigned long) n);
        return WA_ERR_NOT_FOUND;
    }
    for (i = n + 1; i < (size_t) entries->nelts; i++) {
        entry = &APR_ARRAY_IDX(entries, i, struct webauth_keyring_entry);
        APR_ARRAY_IDX(entries, i - 1, struct webauth_keyring_entry) = *entry;
    }
    apr_array_pop(entries);
    return WA_ERR_NONE;
}


/*
 * Given a keyring and a timestamp hint, return the best key in the keyring.
 * The timestamp is used to select the key that was most likely used at that
 * time, given the creation and valid times.
 *
 * The usage argument says whether or not the key will be used for encryption.
 * If it is WA_KEY_ENCRYPT, the hint time is ignored and instead we pick the
 * valid key that will expire the farthest in the future.
 *
 * A pointer to the key is stored in the key argument, and the function
 * returns a WebAuth status code.  This will be WA_ERR_NOT_FOUND if the
 * keyring is empty, has no valid keys, or (for decryption) has no keys with a
 * valid_after time prior to or equal to the hint.
 */
int
webauth_keyring_best_key(struct webauth_context *ctx,
                         const struct webauth_keyring *ring,
                         enum webauth_key_usage usage, time_t hint,
                         const struct webauth_key **output)
{
    size_t i;
    time_t now, valid;
    struct webauth_keyring_entry *best, *entry;

    *output = NULL;
    now = time(NULL);
    best = NULL;
    for (i = 0; i < (size_t) ring->entries->nelts; i++) {
        entry = &APR_ARRAY_IDX(ring->entries, i, struct webauth_keyring_entry);
        valid = entry->valid_after;
        if (valid > now)
            continue;
        if (usage == WA_KEY_ENCRYPT) {
            if (best == NULL || valid > best->valid_after)
                best = entry;
        } else {
            if (best == NULL || (hint >= valid && valid >= best->valid_after))
                best = entry;
        }
    }
    if (best == NULL) {
        webauth_error_set(ctx, WA_ERR_NOT_FOUND, "no valid keys found");
        return WA_ERR_NOT_FOUND;
    } else {
        *output = best->key;
        return WA_ERR_NONE;
    }
}


/*
 * Read in the entirety of a file, continuing after partial reads or signal
 * interruptions.  Takes the WebAuth context, the file name, and pointers into
 * which to store the newly allocated buffer and length.  Returns a WebAuth
 * error code.
 *
 * FIXME: Currently does no locking.
 */
static int
read_keyring_file(struct webauth_context *ctx, const char *path,
                  char **output, size_t *length)
{
    int fd = -1;
    struct stat st;
    size_t size, total;
    char *buf;
    ssize_t nread;
    int status;

    /* Set output parameters in case of error. */
    *output = NULL;
    *length = 0;

    /* Open the file. */
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        status = WA_ERR_KEYRING_OPENREAD;
        webauth_error_set(ctx, status, "cannot read keyring file %s: %s",
                          path, strerror(errno));
        return status;
    }
    if (fstat(fd, &st) < 0) {
        status = WA_ERR_KEYRING_READ;
        webauth_error_set(ctx, status, "cannot stat keyring file %s: %s",
                          path, strerror(errno));
        goto done;
    }

    /* Allocate enough room for the contents. */
    size = st.st_size;
    if (size == 0) {
        status = WA_ERR_KEYRING_READ;
        webauth_error_set(ctx, status, "keyring file %s is empty", path);
        goto done;
    }
    buf = apr_palloc(ctx->pool, size);

    /* Read the contents, looping on interruptions and partial reads. */
    total = 0;
    while (total < size) {
        nread = read(fd, buf + total, size - total);
        if (nread < 0) {
            if (errno == EINTR)
                continue;
            status = WA_ERR_KEYRING_READ;
            webauth_error_set(ctx, status, "cannot read keyring file %s: %s",
                              path, strerror(errno));
            goto done;
        } else if (nread == 0) {
            status = WA_ERR_KEYRING_READ;
            webauth_error_set(ctx, status,
                              "keyring file %s modified during read", path);
            goto done;
        }
        total += nread;
    }
    *output = buf;
    *length = size;
    status = WA_ERR_NONE;

done:
    if (fd >= 0)
        close(fd);
    return status;
}


/*
 * Macros for decoding attributes, which make code easier to read and audit.
 * These macros require that ctx be the context, alist be the attribute list,
 * status be available to and that the correct thing to do on an error is to
 * set an error and go to the done label.
 *
 * a is the attribute code, n is the name of the attribute (for errors), and
 * o is the location into which to store it.  l is the location in which to
 * store the length.
 */
#define DECODE_CHECK(status, n)                                         \
    if (status != WA_ERR_NONE) {                                        \
        webauth_error_set(ctx, status, "error decoding " n " from"      \
                          " keyring file");                             \
        goto done;                                                      \
    }
#define DECODE_DATA(a, n, o, l)                                         \
    do {                                                                \
        status = webauth_attr_list_get(alist, (a), (o), (l),            \
                                       WA_F_FMT_HEX);                   \
        DECODE_CHECK(status, n);                                        \
    } while (0)
#define DECODE_TIME(a, n, o)                                            \
    do {                                                                \
        status = webauth_attr_list_get_time(alist, (a), (o),            \
                                            WA_F_FMT_STR);              \
        DECODE_CHECK(status, n);                                        \
    } while (0)
#define DECODE_UINT(a, n, o)                                            \
    do {                                                                \
        status = webauth_attr_list_get_uint32(alist, (a), (o),          \
                                              WA_F_FMT_STR);            \
        DECODE_CHECK(status, n);                                        \
    } while (0)

/*
 * Variants that decode the i'th attribute of a type.  Assumes the buffer name
 * is available to store the attribute name.
 */
#define DECODE_DATA_N(a, i, n, o, l)                            \
    do {                                                        \
        snprintf(name, sizeof(name), (a), (unsigned long) i);   \
        DECODE_DATA(name, n, (o), (l));                         \
    } while (0)
#define DECODE_TIME_N(a, i, n, o)                               \
    do {                                                        \
        snprintf(name, sizeof(name), (a), (unsigned long) i);   \
        DECODE_TIME(name, n, (o));                              \
    } while (0)
#define DECODE_UINT_N(a, i, n, o)                               \
    do {                                                        \
        snprintf(name, sizeof(name), (a), (unsigned long) i);   \
        DECODE_UINT(name, n, (o));                              \
    } while (0)


/*
 * Decode the encoded form of a keyring into a new keyring structure and store
 * that in the ring argument.  Returns a WA_ERR code.
 */
static int
decode(struct webauth_context *ctx, char *input, size_t length,
       struct webauth_keyring **output)
{
    size_t i;
    int status;
    uint32_t version, count;
    WEBAUTH_ATTR_LIST *alist = NULL;
    struct webauth_keyring *ring;

    /* Get basic information and create the keyring. */
    *output = NULL;
    status = webauth_attrs_decode(input, length, &alist);
    if (status != WA_ERR_NONE) {
        webauth_error_set(ctx, status, "error decoding keyring file");
        goto done;
    }
    DECODE_UINT(A_VERSION, "version", &version);
    if (version != KEYRING_VERSION) {
        status = WA_ERR_KEYRING_VERSION;
        webauth_error_set(ctx, status, "unsupported keyring file version");
        goto done;
    }
    DECODE_UINT(A_NUM_ENTRIES, "key count", &count);
    ring = webauth_keyring_new(ctx, count);

    /* For each key in the file, decode it and store it in the keyring. */
    for (i = 0; i < count; i++) {
        time_t creation, valid_after;
        uint32_t key_type;
        char name[32];
        void *key_data;
        uint32_t key_len;
        struct webauth_key *key;

        DECODE_TIME_N(A_CREATION_TIME, i, "key creation", &creation);
        DECODE_TIME_N(A_VALID_AFTER, i, "key valid after", &valid_after);
        DECODE_UINT_N(A_KEY_TYPE, i, "key type", &key_type);
        DECODE_DATA_N(A_KEY_DATA, i, "key data", &key_data, &key_len);
        status = webauth_key_create(ctx, key_type, key_len, key_data, &key);
        if (status != WA_ERR_NONE)
            goto done;
        webauth_keyring_add(ctx, ring, creation, valid_after, key);
    }
    *output = ring;

done:
    if (alist != NULL)
        webauth_attr_list_free(alist);
    return status;
}


/*
 * Read the encoded form of a keyring from the given file and decode it,
 * storing it in the ring argument.  Returns a WA_ERR code.
 */
int
webauth_keyring_read(struct webauth_context *ctx, const char *path,
                     struct webauth_keyring **ring)
{
    int status;
    char *buf;
    size_t length;

    *ring = NULL;
    status = read_keyring_file(ctx, path, &buf, &length);
    if (status != WA_ERR_NONE)
        return status;
    return decode(ctx, buf, length, ring);
}


/*
 * Macros for encoding attributes, which make code easier to read and audit.
 * These macros require that ctx be the context, alist be the attribute list,
 * status be available to and that the correct thing to do on an error is to
 * set an error and go to the done label.
 *
 * a is the attribute code, n is the name of the attribute (for errors), and
 * v is the value.  l is the length for data attributes.
 */
#define ENCODE_CHECK(status, n)                                         \
    if (status != WA_ERR_NONE) {                                        \
        webauth_error_set(ctx, status, "error encoding " n " to"        \
                          " keyring file");                             \
        goto done;                                                      \
    }
#define ENCODE_DATA(a, n, v, l)                                         \
    do {                                                                \
        status = webauth_attr_list_add(alist, (a), (v), (l),            \
                                       WA_F_COPY_BOTH | WA_F_FMT_HEX);  \
        ENCODE_CHECK(status, n);                                        \
    } while (0)
#define ENCODE_TIME(a, n, v)                                            \
    do {                                                                \
        status = webauth_attr_list_add_time(alist, (a), (v),            \
                     WA_F_COPY_NAME | WA_F_FMT_STR);                    \
        ENCODE_CHECK(status, n);                                        \
    } while (0)
#define ENCODE_UINT(a, n, v)                                            \
    do {                                                                \
        status = webauth_attr_list_add_uint32(alist, (a), (v),          \
                     WA_F_COPY_NAME | WA_F_FMT_STR);                    \
        ENCODE_CHECK(status, n);                                        \
    } while (0)

/*
 * Variants that decode the i'th attribute of a type.  Assumes the buffer name
 * is available to store the attribute name.
 */
#define ENCODE_DATA_N(a, i, n, v, l)                            \
    do {                                                        \
        snprintf(name, sizeof(name), (a), (unsigned long) i);   \
        ENCODE_DATA(name, n, (v), (l));                         \
    } while (0)
#define ENCODE_TIME_N(a, i, n, v)                               \
    do {                                                        \
        snprintf(name, sizeof(name), (a), (unsigned long) i);   \
        ENCODE_TIME(name, n, (v));                              \
    } while (0)
#define ENCODE_UINT_N(a, i, n, v)                               \
    do {                                                        \
        snprintf(name, sizeof(name), (a), (unsigned long) i);   \
        ENCODE_UINT(name, n, (v));                              \
    } while (0)


/*
 * Encode a keyring into the format for the file on disk.  See the comments at
 * the top of this file for the format.  Stores the encoded keyring in buffer
 * (allocating new memory for it) and the length of the encoded buffer in
 * buffer_len.  Returns an WA_ERR code.
 */
static int
encode(struct webauth_context *ctx, const struct webauth_keyring *ring,
       char **output, size_t *length)
{
    size_t i, attr_len;
    WEBAUTH_ATTR_LIST *alist = NULL;
    int status;
    char *buf;

    *output = NULL;
    alist = webauth_attr_list_new(ring->entries->nelts * 5 + 2);
    if (alist == NULL) {
        status = WA_ERR_NO_MEM;
        webauth_error_set(ctx, status, "cannot create attribute list");
        goto done;
    }
    ENCODE_UINT(A_VERSION, "version", KEYRING_VERSION);
    ENCODE_UINT(A_NUM_ENTRIES, "key count", ring->entries->nelts);
    for (i = 0; i < (size_t) ring->entries->nelts; i++) {
        char name[32];
        struct webauth_keyring_entry *entry;

        entry = &APR_ARRAY_IDX(ring->entries, i, struct webauth_keyring_entry);
        ENCODE_TIME_N(A_CREATION_TIME, i, "key creation", entry->creation);
        ENCODE_TIME_N(A_VALID_AFTER, i, "key valid after", entry->valid_after);
        ENCODE_UINT_N(A_KEY_TYPE, i, "key type", entry->key->type);
        ENCODE_DATA_N(A_KEY_DATA, i, "key data", entry->key->data,
                      entry->key->length);
    }
    attr_len = webauth_attrs_encoded_length(alist);
    buf = apr_palloc(ctx->pool, attr_len);
    status = webauth_attrs_encode(alist, buf, length, attr_len);
    if (status != WA_ERR_NONE) {
        webauth_error_set(ctx, status, "cannot encode keyring attributes");
        *length = 0;
        goto done;
    }
    *output = buf;

done:
    if (alist != NULL)
        webauth_attr_list_free(alist);
    return status;
}


/*
 * Write a keyring to the given file in encoded format.  Returns a WA_ERR
 * code.
 */
int
webauth_keyring_write(struct webauth_context *ctx,
                      const struct webauth_keyring *ring, const char *path)
{
    int status;
    int fd = -1;
    size_t length;
    ssize_t nwrite;
    char *temp, *buf;

    /* Create a temporary file for the new copy of the keyring. */
    temp = apr_psprintf(ctx->pool, "%s.XXXXXX", path);
    fd = mkstemp(temp);
    if (fd < 0) {
        status = WA_ERR_KEYRING_OPENWRITE;
        webauth_error_set(ctx, status, "cannot create temporary keyring file"
                          "%s.XXXXXX: %s", path, strerror(errno));
        goto done;
    }

    /* Encode and write out the file. */
    status = encode(ctx, ring, &buf, &length);
    if (status != WA_ERR_NONE)
        goto done;
    nwrite = write(fd, buf, length);
    if (nwrite < 0 || (size_t) nwrite != length || close(fd) < 0) {
        status = WA_ERR_KEYRING_WRITE;
        webauth_error_set(ctx, status, "error writing to temporary keyring"
                          " file %s: %s", temp, strerror(errno));
        goto done;
    }
    fd = -1;

    /* Rename the new file over the old path. */
    if (rename(temp, path) < 0) {
        status = WA_ERR_KEYRING_WRITE;
        webauth_error_set(ctx, status, "cannot rename temporary keyring file"
                          " %s to %s: %s", temp, path, strerror(errno));
        goto done;
    }
    status = WA_ERR_NONE;

done:
    /* Should be -1 and closed by now, else an error occured. */
    if (fd >= 0) {
        close(fd);
        unlink(temp);
    }
    return status;
}


/*
 * Create a new keyring initialized with a single new random key and write it
 * to the specified path.  Used to create a new keyring file when none
 * exists.  Also stores the newly generated keyring in the ring argument.
 * Returns a WA_ERR status code.
 */
static int
new_ring(struct webauth_context *ctx, const char *path,
         struct webauth_keyring **ring)
{
    struct webauth_key *key;
    int status;
    time_t now;

    status = webauth_key_create(ctx, WA_AES_KEY, WA_AES_128, NULL, &key);
    if (status != WA_ERR_NONE)
        return status;
    *ring = webauth_keyring_new(ctx, 1);
    now = time(NULL);
    webauth_keyring_add(ctx, *ring, now, now, key);
    return webauth_keyring_write(ctx, *ring, path);
}


/*
 * Check the keyring provided in ring to be sure that the key with the most
 * recent valid-after time is at least lifetime seconds ago.  If it is not,
 * create a new random key, add it to the keyring, and write the modified
 * keyring to the specified file path.  If we had to update the keyring, set
 * the updated argument to WA_KAU_UPDATE.  Returns a WA_ERR code.
 */
static int
check_ring(struct webauth_context *ctx, const char *path,
           unsigned long lifetime, struct webauth_keyring *ring,
           enum webauth_kau_status *updated)
{
    time_t now;
    struct webauth_key *key;
    struct webauth_keyring_entry *entry;
    int status;
    size_t i;

    /*
     * See if we have at least one key whose valid_after + lifetime is still
     * greater then current time.
     */
    now = time(NULL);
    for (i = 0; i < (size_t) ring->entries->nelts; i++) {
        entry = &APR_ARRAY_IDX(ring->entries, i, struct webauth_keyring_entry);
        if (entry->valid_after + (time_t) lifetime > now)
            return WA_ERR_NONE;
    }

    /* We don't have a recent enough key.  Add a new one. */
    *updated = WA_KAU_UPDATE;
    status = webauth_key_create(ctx, WA_AES_KEY, WA_AES_128, NULL, &key);
    if (status != WA_ERR_NONE)
        return status;
    webauth_keyring_add(ctx, ring, now, now, key);
    return webauth_keyring_write(ctx, ring, path);
}


/*
 * Automatically update a keyring.  This means that if the keyring at path
 * doesn't already exist, create a new one if the boolean variable create is
 * set (otherwise return an error) and set updated to WA_KAU_CREATE.
 *
 * If the keyring does already exist, check whether the key with the most
 * recent valid-after time became valid more than lifetime seconds ago.  If
 * so, add a new random key to the keyring and write it out again, setting
 * updated to WA_KAU_UPDATE if successful and storing the return code of the
 * keyring update in update_status.
 *
 * Regardless, set ring to the keyring read from path, after whatever
 * modifications were necessary.
 *
 * Returns a WA_ERR code.
 */
int
webauth_keyring_auto_update(struct webauth_context *ctx, const char *path,
                            int create, unsigned long lifetime,
                            struct webauth_keyring **ring,
                            enum webauth_kau_status *updated,
                            int *update_status)
{
    int status;

    *updated = WA_KAU_NONE;
    *update_status = WA_ERR_NONE;
    status = webauth_keyring_read(ctx, path, ring);
    if (status != WA_ERR_NONE) {
        if (!create)
            return status;
        *updated = WA_KAU_CREATE;
        return new_ring(ctx, path, ring);
    }
    if (lifetime > 0)
        *update_status = check_ring(ctx, path, lifetime, *ring, updated);
    return status;
}
