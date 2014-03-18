/*
 * Handling of keys and keyrings.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2004, 2005, 2006, 2009, 2010, 2012, 2013, 2014
 *    The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <errno.h>
#include <sys/stat.h>
#include <time.h>

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/keys.h>

/* The version of the keyring file format that we implement. */
#define KEYRING_VERSION 1


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

    if (n >= (size_t) entries->nelts) {
        wai_error_set(ctx, WA_ERR_NOT_FOUND, "keyring index %lu out of range",
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
            if (hint >= valid && (best == NULL || valid >= best->valid_after))
                best = entry;
        }
    }
    if (best == NULL)
        return wai_error_set(ctx, WA_ERR_NOT_FOUND, "no valid keys");
    else {
        *output = best->key;
        return WA_ERR_NONE;
    }
}


/*
 * Decode the encoded form of a keyring into a new keyring structure and store
 * that in the ring argument.  Returns a WA_ERR code.
 */
int
webauth_keyring_decode(struct webauth_context *ctx, const char *input,
                       size_t length, struct webauth_keyring **output)
{
    size_t i;
    int s;
    struct webauth_keyring *ring;
    struct wai_keyring data;

    /*
     * Decode the keyring to our internal data structure and check the file
     * format version.
     */
    *output = NULL;
    memset(&data, 0, sizeof(data));
    s = wai_decode(ctx, wai_keyring_encoding, input, length, &data);
    if (s != WA_ERR_NONE)
        return s;
    if (data.version != KEYRING_VERSION) {
        s = WA_ERR_FILE_VERSION;
        return wai_error_set(ctx, s, "keyring version %d", data.version);
    }

    /*
     * Convert the internal data structure to our keyring data structure and,
     * while doing so, sanity-check the data that we read by using our regular
     * API functions to turn it into keys and keyring entries.
     */
    ring = webauth_keyring_new(ctx, data.entry_count);
    for (i = 0; i < data.entry_count; i++) {
        struct wai_keyring_entry *entry;
        struct webauth_key *key;

        entry = &data.entry[i];
        s = webauth_key_create(ctx, entry->key_type, entry->key_len,
                               entry->key, &key);
        if (s != WA_ERR_NONE)
            return s;
        webauth_keyring_add(ctx, ring, entry->creation, entry->valid_after,
                            key);
    }
    *output = ring;
    return WA_ERR_NONE;
}


/*
 * Read the encoded form of a keyring from the given file and decode it,
 * storing it in the ring argument.  Returns a WA_ERR code.  We do not do any
 * locking for reads and instead rely on atomic replacement of the keyring on
 * update (although we do read the keyring within a lock while doing
 * auto-update).
 */
int
webauth_keyring_read(struct webauth_context *ctx, const char *path,
                     struct webauth_keyring **ring)
{
    int s;
    void *buf;
    size_t length;

    *ring = NULL;
    s = wai_file_read(ctx, path, &buf, &length);
    if (s != WA_ERR_NONE)
        return s;
    return webauth_keyring_decode(ctx, buf, length, ring);
}


/*
 * Encode a keyring into the format for the file on disk.  Stores the encoded
 * keyring in buffer (allocating new memory for it) and the length of the
 * encoded buffer in buffer_len.  Returns an WA_ERR code.
 */
int
webauth_keyring_encode(struct webauth_context *ctx,
                       const struct webauth_keyring *ring, char **output,
                       size_t *length)
{
    struct wai_keyring data;
    size_t i, size;

    /*
     * Convert the keyring into the struct wai_keyring format, which is what
     * we will serialize to disk.
     */
    *output = NULL;
    memset(&data, 0, sizeof(data));
    data.version = KEYRING_VERSION;
    data.entry_count = ring->entries->nelts;
    size = sizeof(struct wai_keyring_entry) * data.entry_count;
    data.entry = apr_palloc(ctx->pool, size);
    for (i = 0; i < (size_t) ring->entries->nelts; i++) {
        struct webauth_keyring_entry *entry;

        entry = &APR_ARRAY_IDX(ring->entries, i, struct webauth_keyring_entry);
        data.entry[i].creation = entry->creation;
        data.entry[i].valid_after = entry->valid_after;
        data.entry[i].key_type = entry->key->type;
        data.entry[i].key = entry->key->data;
        data.entry[i].key_len = entry->key->length;
    }

    /* Do the encoding. */
    return wai_encode(ctx, wai_keyring_encoding, &data, (void **) output,
                      length);
}


/*
 * Write a keyring to the given file in encoded format.  Returns a WA_ERR
 * code.  This is the internal function that does no locking.
 *
 * We unfortunately have to use POSIX I/O functions since APR doesn't have
 * equivalents of fchown or fchmod.
 */
static int
write_keyring(struct webauth_context *ctx, const struct webauth_keyring *ring,
              const char *path)
{
    struct stat st;
    bool sync_perms = false;
    bool group_set = false;
    int fd = -1;
    size_t length;
    ssize_t result;
    char *temp, *buf;
    apr_status_t code;
    mode_t mode;
    int s;

    /* Get the ownership and mode of the existing file. */
    if (stat(path, &st) == 0)
        sync_perms = true;
    else if (errno != ENOENT) {
        s = WA_ERR_FILE_READ;
        return wai_error_set_system(ctx, s, errno, "stat %s", path);
    }

    /* Create a temporary file for the new copy of the keyring. */
    temp = apr_psprintf(ctx->pool, "%s.XXXXXX", path);
    fd = mkstemp(temp);
    if (fd < 0) {
        s = WA_ERR_FILE_OPENWRITE;
        wai_error_set_system(ctx, s, errno, "temporary keyring %s", temp);
        return s;
    }

    /*
     * Set ownership and permissions.  Ignore failures of fchown with EPERM,
     * as this probably indicates that we're rewriting a keyring owned by
     * someone else and we're not root.  Assume that whoever created such a
     * situation knew what they were doing and has appropriate permissions.
     *
     * Change the group first, since it's the most likely to succeed, and then
     * the user.
     */
    if (sync_perms) {
        if (fchown(fd, -1, st.st_gid) == 0)
            group_set = true;
        else if (errno != EPERM) {
            s = WA_ERR_FILE_WRITE;
            wai_error_set_system(ctx, s, errno, "group of %s", temp);
            goto done;
        }
        if (fchown(fd, st.st_uid, -1) < 0 && errno != EPERM) {
            s = WA_ERR_FILE_WRITE;
            wai_error_set_system(ctx, s, errno, "group of %s", temp);
            goto done;
        }

        /*
         * Don't sync permissions if the include group read or write and we
         * weren't able to set the group.
         */
        mode = st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
        if (group_set || !(mode & (S_IRGRP | S_IWGRP)))
            if (fchmod(fd, mode) < 0) {
                s = WA_ERR_FILE_WRITE;
                wai_error_set_system(ctx, s, errno, "mode of %s", temp);
                goto done;
            }
    }

    /* Encode and write out the file. */
    s = webauth_keyring_encode(ctx, ring, &buf, &length);
    if (s != WA_ERR_NONE)
        goto done;
    result = write(fd, buf, length);
    if (result < 0 || (size_t) result != length) {
        s = WA_ERR_FILE_WRITE;
        wai_error_set_system(ctx, s, errno, "temporary keyring %s", temp);
        goto done;
    }
    close(fd);
    fd = -1;

    /* Rename the new file over the old path. */
    code = apr_file_rename(temp, path, ctx->pool);
    if (code != APR_SUCCESS) {
        s = WA_ERR_FILE_WRITE;
        wai_error_set_apr(ctx, s, code, "renaming %s to %s", temp, path);
        goto done;
    }
    s = WA_ERR_NONE;

done:
    if (fd >= 0) {
        close(fd);
        apr_file_remove(temp, ctx->pool);
    }
    return s;
}


/*
 * Public wrapper around write_keyring with locking.
 */
int
webauth_keyring_write(struct webauth_context *ctx,
                      const struct webauth_keyring *ring, const char *path)
{
    int s;
    apr_file_t *lock;

    s = wai_file_lock(ctx, path, &lock);
    if (s != WA_ERR_NONE)
        return s;
    s = write_keyring(ctx, ring, path);
    wai_file_unlock(ctx, path, lock);
    return s;
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
    int s;
    time_t now;

    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_128, NULL, &key);
    if (s != WA_ERR_NONE)
        return s;
    *ring = webauth_keyring_new(ctx, 1);
    now = time(NULL);
    webauth_keyring_add(ctx, *ring, now, now, key);
    return write_keyring(ctx, *ring, path);
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
    int s;
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
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_128, NULL, &key);
    if (s != WA_ERR_NONE)
        return s;
    webauth_keyring_add(ctx, ring, now, now, key);
    return write_keyring(ctx, ring, path);
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
    int s;
    apr_file_t *lock;

    /* Set output variables in case of an error. */
    *updated = WA_KAU_NONE;
    *update_status = WA_ERR_NONE;

    /*
     * Lock the keyring so that the read, possible creation, and possible
     * update is done once and atomically.
     */
    s = wai_file_lock(ctx, path, &lock);
    if (s != WA_ERR_NONE)
        return s;

    /* Read and possibly create or update the keyring. */
    s = webauth_keyring_read(ctx, path, ring);
    if (s != WA_ERR_NONE) {
        if (!create || s != WA_ERR_FILE_NOT_FOUND)
            goto done;
        *updated = WA_KAU_CREATE;
        s = new_ring(ctx, path, ring);
        goto done;
    }
    if (lifetime > 0)
        *update_status = check_ring(ctx, path, lifetime, *ring, updated);

done:
    wai_file_unlock(ctx, path, lock);
    return s;
}
