/*
 * Handling of keys and keyrings.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2004, 2005, 2006, 2009, 2010
 *    Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <lib/webauthp.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#if HAVE_UNISTD_H
# include <unistd.h>
#endif

/* The version of the keyring file format that we implement. */
#define KEYRING_VERSION 1

/*
 * A keyring file as implemented in this code is a bunch of attributes.  Here
 * are the attributes and the types of their values:
 *
 *     v={version}           uiunt32_t
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
#define A_CREATION_TIME "ct%d"
#define A_VALID_AFTER   "va%d"
#define A_KEY_TYPE      "kt%d"
#define A_KEY_DATA      "kd%d"


/*
 * Construct a new WebAuth key from the key type, data, and length.  This does
 * not generate a new random key or new key material.  It creates a key
 * structure from the component values.  Returns the newly-allocated key or
 * NULL on failure to allocate memory.
 */
WEBAUTH_KEY *
webauth_key_create(unsigned int type, const char *key, size_t len)
{
    WEBAUTH_KEY *k;

    assert(key != NULL);

    if (type != WA_AES_KEY)
        return NULL;
    if (len != WA_AES_128 && len != WA_AES_192 && len != WA_AES_256)
        return NULL;

    k = malloc(sizeof(WEBAUTH_KEY));
    if (k == NULL)
        return NULL;

    k->data = malloc(len);
    if (k->data == NULL) {
        free(k);
        return NULL;
    }

    k->type = type;
    k->length = len;
    memcpy(k->data, key, len);
    return k;
}


/*
 * Create a deep copy of a key structure.  Returns the newly allocated key or
 * NULL on failure to allocate memory.
 */
WEBAUTH_KEY *
webauth_key_copy(const WEBAUTH_KEY *key)
{
    WEBAUTH_KEY *copy;

    assert(key != NULL);
    assert(key->data != NULL);

    copy = malloc(sizeof(WEBAUTH_KEY));
    if (copy==NULL)
        return NULL;

    copy->type = key->type;
    copy->length = key->length;
    copy->data = malloc(copy->length);

    memcpy(copy->data, key->data, copy->length);
    return copy;
}


/*
 * Free a key structure.
 */
void
webauth_key_free(WEBAUTH_KEY *key)
{
    assert(key != NULL);

    memset(key->data, 0, key->length);
    free(key->data);
    free(key);
}


/*
 * Create a new keyring.  Takes one argument specifying the initial capacity
 * of the keyring.  Returns the newly allocated structure or NULL on failure
 * to allocate memory.
 */
WEBAUTH_KEYRING *
webauth_keyring_new(size_t initial_capacity)
{
    WEBAUTH_KEYRING *ring;

    /*
     * Make sure the initial capacity is at least 1, since otherwise we try
     * to malloc 0 bytes of memory, often returning NULL.
     */
    if (initial_capacity < 1)
        initial_capacity = 1;

    ring = malloc(sizeof(WEBAUTH_KEYRING));
    if (ring != NULL) {
        ring->num_entries = 0;
        ring->capacity = initial_capacity;
        ring->entries =
            malloc(sizeof(WEBAUTH_KEYRING_ENTRY) * initial_capacity);
        if (ring->entries == NULL) {
            free(ring);
            return NULL;
        }
    }
    return ring;
}


/*
 * Free a keyring, including all of its keys.
 */
void
webauth_keyring_free(WEBAUTH_KEYRING *ring)
{
    size_t i;

    assert(ring);

    for (i = 0; i < ring->num_entries; i++)
        webauth_key_free(ring->entries[i].key);
    free(ring->entries);
    free(ring);
}


/*
 * Add a key to a keyring.  Takes the ring, the creation time, the time at
 * which the key becomes valid, and the key.  Either of the times may be zero,
 * in which case the current time is used.  Returns a WA_ERR code.
 */
int
webauth_keyring_add(WEBAUTH_KEYRING *ring, time_t creation_time,
                    time_t valid_after, WEBAUTH_KEY *key)
{
    assert(ring);
    assert(key);

    if (ring->num_entries == ring->capacity) {
        size_t new_capacity = ring->capacity * 2;
        size_t new_size = sizeof(WEBAUTH_KEYRING_ENTRY) * new_capacity;
        WEBAUTH_KEYRING_ENTRY *new_entries = realloc(ring->entries, new_size);

        if (new_entries == NULL)
            return WA_ERR_NO_MEM;
        ring->capacity = new_capacity;
        if (ring->entries != new_entries)
            ring->entries = new_entries;
    }

    if (creation_time == 0 || valid_after == 0) {
        time_t curr = time(NULL);

        if (creation_time == 0)
            creation_time = curr;
        if (valid_after == 0)
            valid_after = curr;
    }
    ring->entries[ring->num_entries].creation_time = creation_time;
    ring->entries[ring->num_entries].valid_after = valid_after;
    ring->entries[ring->num_entries].key = webauth_key_copy(key);
    if (ring->entries[ring->num_entries].key == NULL)
        return WA_ERR_NO_MEM;
    ring->num_entries++;
    return WA_ERR_NONE;
}


/*
 * Remove a key from a keyring by index and free the key.  Returns a WA_ERR
 * code.
 */
int
webauth_keyring_remove(WEBAUTH_KEYRING *ring, size_t index)
{
    size_t i;

    assert(ring);

    if (index >= ring->num_entries)
        return WA_ERR_NOT_FOUND;
    webauth_key_free(ring->entries[index].key);
    for (i = index+1; i < ring->num_entries; i++)
        ring->entries[i-1] = ring->entries[i];
    ring->num_entries--;
    return WA_ERR_NONE;
}


/*
 * Given a keyring and a timestamp hint, return the best key in the keyring.
 * The timestamp is used to select the key that was most likely used at that
 * time, given the creation and valid times.
 *
 * The encryption flag says whether or not the key will be used for
 * encryption.  If it is set, the hint time is ignored and instead we pick the
 * key that will expire the farthest in the future.
 */
WEBAUTH_KEY *
webauth_keyring_best_key(const WEBAUTH_KEYRING *ring, int encryption,
                         time_t hint)
{
    size_t i;
    time_t curr;
    WEBAUTH_KEYRING_ENTRY *b, *e;

    assert(ring);

    time(&curr);

    if (ring->num_entries == 0)
        return NULL;

    b = NULL;
    for (i = 0; i < ring->num_entries; i++) {
        e = &ring->entries[i];
        if (encryption) {
            if (e->valid_after > curr)
                continue;
            if (b == NULL || e->valid_after > b->valid_after)
                b = e;
        } else {
            if (e->valid_after > curr)
                continue;
            if ((b == NULL) ||
                (hint >= e->valid_after && e->valid_after >= b->valid_after))
                b = e;
        }
    }
    return  (b != NULL) ? b->key : NULL;
}


/*
 * Helper function to read the entirety of a file descriptor, continuing after
 * partial reads or syscall interruptions from signals.  Takes the same
 * arguments and returns the same value as the read system call.
 */
static ssize_t
read_fully(int fd, char *buff, size_t n)
{
    size_t tot = 0;
    ssize_t num_read;

    while (tot != n) {
        num_read = read(fd, buff + tot, n - tot);
        if (num_read < 0) {
            if (errno != EINTR)
                return num_read;
        } else
            tot += num_read;
    }
    return tot;
}


/*
 * Encode a keyring into the format for the file on disk.  See the comments at
 * the top of this file for the format.  Stores the encoded keyring in buffer
 * (allocating new memory for it) and the length of the encoded buffer in
 * buffer_len.  Returns an WA_ERR code.
 */
int
webauth_keyring_encode(WEBAUTH_KEYRING *ring, char **buffer,
                       size_t *buffer_len)
{
    size_t i, attr_len;
    WEBAUTH_ATTR_LIST *alist;
    int status;
    char name[32];

    assert(ring);
    assert(buffer);
    assert(buffer_len);

    *buffer = NULL;
    alist = NULL;

    alist = webauth_attr_list_new(ring->num_entries * 5 + 2);
    if (alist == NULL) {
        status = WA_ERR_NO_MEM;
        goto cleanup;
    }

    status = webauth_attr_list_add_uint32(alist, A_VERSION, KEYRING_VERSION,
                                          WA_F_FMT_STR);
    if (status != WA_ERR_NONE)
        goto cleanup;

    status = webauth_attr_list_add_uint32(alist, A_NUM_ENTRIES,
                                          ring->num_entries, WA_F_FMT_STR);
    if (status != WA_ERR_NONE)
        goto cleanup;

    for (i = 0; i < ring->num_entries; i++) {
        sprintf(name, A_CREATION_TIME, i);
        status = webauth_attr_list_add_time(alist, name,
                                            ring->entries[i].creation_time,
                                            WA_F_COPY_NAME | WA_F_FMT_STR);
        if (status != WA_ERR_NONE)
            goto cleanup;

        sprintf(name, A_VALID_AFTER, i);
        status = webauth_attr_list_add_time(alist, name,
                                            ring->entries[i].valid_after,
                                            WA_F_COPY_NAME | WA_F_FMT_STR);
        if (status != WA_ERR_NONE)
            goto cleanup;

        sprintf(name, A_KEY_TYPE, i);
        status = webauth_attr_list_add_uint32(alist, name,
                                              ring->entries[i].key->type,
                                              WA_F_COPY_NAME | WA_F_FMT_STR);
        if (status != WA_ERR_NONE)
            goto cleanup;

        sprintf(name, A_KEY_DATA, i);
        status = webauth_attr_list_add(alist, name,
                                       ring->entries[i].key->data,
                                       ring->entries[i].key->length,
                                       WA_F_COPY_BOTH | WA_F_FMT_HEX);
        if (status != WA_ERR_NONE)
            goto cleanup;
    }

    attr_len = webauth_attrs_encoded_length(alist);
    *buffer = malloc(attr_len);
    if (*buffer == NULL) {
        status = WA_ERR_NO_MEM;
        goto cleanup;
    }
    status = webauth_attrs_encode(alist, *buffer, buffer_len, attr_len);
    if (status != WA_ERR_NONE)
        goto cleanup;

    status = WA_ERR_NONE;

 cleanup:
    if (alist != NULL)
        webauth_attr_list_free(alist);
    if (status != WA_ERR_NONE && *buffer != NULL) {
        free(*buffer);
        *buffer = NULL;
    }
    return status;
}


/*
 * Write a keyring to the given file in encoded format.  Returns a WA_ERR
 * code.
 */
int
webauth_keyring_write_file(WEBAUTH_KEYRING *ring, const char *path)
{
    int fd;
    size_t attr_len;
    ssize_t written;
    char *attr_buff;
    int status, retry;
    char *temp;

    assert(ring);

    attr_buff = NULL;
    temp = NULL;
    fd = -1;

    /* Allocate space for the temporary file.  Add .XXXXXX and a nul. */
    temp = malloc(strlen(path) + 7 + 1);
    if (temp == NULL)
        return WA_ERR_NO_MEM;

    retry = 0;
    fd = -1;
    while (fd == -1 && retry++ < 10) {
        sprintf(temp, "%s.XXXXXX", path);
        mktemp(temp);
        fd = open(temp, O_WRONLY | O_TRUNC | O_CREAT | O_EXCL, 0600);
        if (fd == -1 && errno != EEXIST) {
            status = WA_ERR_KEYRING_OPENWRITE;
            goto cleanup;
        }
    }

    status = webauth_keyring_encode(ring, &attr_buff, &attr_len);
    if (status != WA_ERR_NONE)
        goto cleanup;

    written = write(fd, attr_buff, attr_len);
    if (written < 0 || (size_t) written != attr_len) {
        status = WA_ERR_KEYRING_WRITE;
        goto cleanup;
    }

    if (close(fd) != 0) {
        status = WA_ERR_KEYRING_WRITE;
        goto cleanup;
    }
    fd = -1;

    if (rename(temp, path) != 0) {
        status = WA_ERR_KEYRING_WRITE;
        goto cleanup;
    }

    status = WA_ERR_NONE;

 cleanup:
    if (attr_buff != NULL)
        free(attr_buff);

    /* Should be -1 and closed by now, else an error occured. */
    if (fd != -1) {
        close(fd);
        unlink(temp);
    }

    if (temp != NULL)
        free(temp);

    return status;
}


/*
 * Decode the encoded form of a keyring into a new keyring structure and store
 * that in the ring argument.  Returns a WA_ERR code.
 */
int
webauth_keyring_decode(char *buffer, size_t buffer_len,
                       WEBAUTH_KEYRING **ring)
{
    size_t i;
    int s;
    uint32_t version, num_entries;
    WEBAUTH_ATTR_LIST *alist;
    char *key_data;
    size_t key_len;

    assert(buffer);
    assert(ring);

    *ring = NULL;
    alist = NULL;

    s = webauth_attrs_decode(buffer, buffer_len, &alist);
    if (s != WA_ERR_NONE)
        goto cleanup;

    s = webauth_attr_list_get_uint32(alist, A_VERSION, &version, WA_F_FMT_STR);
    if (s != WA_ERR_NONE)
        goto cleanup;

    if (version != KEYRING_VERSION) {
        s = WA_ERR_KEYRING_VERSION;
        goto cleanup;
    }

    s = webauth_attr_list_get_uint32(alist, A_NUM_ENTRIES, &num_entries,
                                     WA_F_FMT_STR);
    if (s != WA_ERR_NONE)
        goto cleanup;

    *ring = webauth_keyring_new(num_entries);

    if (*ring == NULL) {
        s = WA_ERR_NO_MEM;
        goto cleanup;
    }

    for (i = 0; i < num_entries; i++) {
        time_t creation_time, valid_after;
        uint32_t key_type;
        char name[32];
        WEBAUTH_KEY *key;

        sprintf(name, A_CREATION_TIME, i);
        s = webauth_attr_list_get_time(alist, name, &creation_time,
                                       WA_F_FMT_STR);
        if (s != WA_ERR_NONE)
            goto cleanup;

        sprintf(name, A_VALID_AFTER, i);
        s = webauth_attr_list_get_time(alist, name, &valid_after,
                                       WA_F_FMT_STR);
        if (s != WA_ERR_NONE)
            goto cleanup;

        sprintf(name, A_KEY_TYPE, i);
        s = webauth_attr_list_get_uint32(alist, name, &key_type,
                                         WA_F_FMT_STR);
        if (s != WA_ERR_NONE)
            goto cleanup;

        sprintf(name, A_KEY_DATA, i);
        s = webauth_attr_list_get(alist, name, (void *) &key_data, &key_len,
                                  WA_F_FMT_HEX);
        if (s != WA_ERR_NONE)
            goto cleanup;

        key = webauth_key_create(key_type, key_data, key_len);
        if (key == NULL) {
            s = WA_ERR_NO_MEM;
            goto cleanup;
        }

        webauth_keyring_add(*ring, creation_time, valid_after, key);
        webauth_key_free(key);
    }

 cleanup:
    if (alist != NULL)
        webauth_attr_list_free(alist);

    if (s != WA_ERR_NONE && *ring != NULL)
        webauth_keyring_free(*ring);

    return s;
}


/*
 * Read the encoded form of a keyring from the given file and decode it,
 * storing it in the ring argument.  Returns a WA_ERR code.
 */
int
webauth_keyring_read_file(const char *path, WEBAUTH_KEYRING **ring)
{
    int fd;
    ssize_t n;
    size_t len;
    int s;
    struct stat sbuf;
    char *buff;

    *ring = NULL;
    buff = NULL;
    fd = -1;

    /*
     * This currently does no locking and should, since updating a keyring
     * involves reading it, modifying it, and then writing it out again and
     * right now two processes doing that at the same time could lose the
     * changes from one of them.
     */
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        s = WA_ERR_KEYRING_OPENREAD;
        goto cleanup;
    }
    if (fstat(fd, &sbuf) < 0) {
        close(fd);
        s = WA_ERR_KEYRING_READ;
        goto cleanup;
    }
    len = sbuf.st_size;
    if (len == 0) {
        close(fd);
        s = WA_ERR_KEYRING_READ;
        goto cleanup;
    }
    buff = malloc(len);
    if (buff == NULL) {
        s = WA_ERR_NO_MEM;
        goto cleanup;
    }
    n = read_fully(fd, buff, len);
    if (n < 0 || (size_t) n != len) {
        s = WA_ERR_KEYRING_READ;
        goto cleanup;
    }
    s = webauth_keyring_decode(buff, len, ring);
    if (s != WA_ERR_NONE)
        goto cleanup;

 cleanup:
    if (fd != -1)
        close(fd);
    if (s != WA_ERR_NONE && *ring != NULL)
        webauth_keyring_free(*ring);
    if (buff != NULL)
        free(buff);
    return s;
}

/*
 * Create a new keyring initialized with a single new random key and write it
 * to the specified path.  Used to create a new keyring file when none
 * exists.  Also stores the newly generated keyring in the ring argument.
 * Returns a WA_ERR status code.
 */
static int
new_ring(const char *path, WEBAUTH_KEYRING **ring)
{
    WEBAUTH_KEY *key;
    char key_material[WA_AES_128];
    int s;
    time_t curr = time(NULL);
    key = NULL;

    *ring = webauth_keyring_new(5);
    if (*ring == NULL) {
        s = WA_ERR_NO_MEM;
        goto done;
    }
    s = webauth_random_key(key_material, WA_AES_128);
    if (s != WA_ERR_NONE)
        goto done;
    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    if (key == NULL) {
        s =WA_ERR_NO_MEM;
        goto done;
    }
    s = webauth_keyring_add(*ring, curr, curr, key);
    if (s != WA_ERR_NONE)
        goto done;
    s = webauth_keyring_write_file(*ring, path);

done:
    if (key != NULL)
        webauth_key_free(key);
    if (s != WA_ERR_NONE && *ring != NULL)
        webauth_keyring_free(*ring);
    return s;
}


/*
 * Check the keyring provided in ring to be sure that the key with the most
 * recent valid-after time is at least lifetime seconds ago.  If it is not,
 * create a new random key and write the modified keyring to the specified
 * file path.  If we had to update the keyring, set the updated argument to
 * WA_KAU_UPDATE.  Returns a WA_ERR code.
 */
static int
check_ring(const char *path, int lifetime, WEBAUTH_KEYRING *ring,
           WEBAUTH_KAU_STATUS *updated)
{
    time_t curr;
    WEBAUTH_KEY *key;
    int s;
    size_t i;
    char key_material[WA_AES_128];

    time(&curr);

    /*
     * See if we have at least one key whose valid_after + lifetime is
     * still greater then current time.
     */
    for (i = 0; i < ring->num_entries; i++)
        if (ring->entries[i].valid_after + lifetime > curr)
            return WA_ERR_NONE;

    /* If not, add a new key to the keyring and write it out. */
    *updated = WA_KAU_UPDATE;
    s = webauth_random_key(key_material, WA_AES_128);
    if (s != WA_ERR_NONE)
        return s;
    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    if (key == NULL)
        return WA_ERR_NO_MEM;
    s = webauth_keyring_add(ring, curr, curr, key);
    if (s != WA_ERR_NONE) {
        webauth_key_free(key);
        return s;
    }
    webauth_key_free(key);
    return webauth_keyring_write_file(ring, path);
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
webauth_keyring_auto_update(const char *path, int create, int lifetime,
                            WEBAUTH_KEYRING **ring,
                            WEBAUTH_KAU_STATUS *updated,
                            WEBAUTH_ERR *update_status)
{
    int s;

    assert(ring);
    assert(updated);
    assert(update_status);

    *updated = WA_KAU_NONE;
    *update_status = WA_ERR_NONE;
    s = webauth_keyring_read_file(path, ring);
    if (s != WA_ERR_NONE) {
        if (!create)
            return s;
        else {
            *updated = WA_KAU_CREATE;
            return new_ring(path, ring);
        }
    }
    if (lifetime)
        *update_status = check_ring(path, lifetime, *ring, updated);
    return s;
}
