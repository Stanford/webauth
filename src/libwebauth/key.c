#include "webauthp.h"

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

/*
 * construct a new key. 
 */

WEBAUTH_KEY *
webauth_key_create(int type, const unsigned char *key, int len) 
{
    WEBAUTH_KEY *k;

    assert(key != NULL);

    if (type != WA_AES_KEY) {
        return NULL;
    }

    if (len != WA_AES_128 && 
        len != WA_AES_192 &&
        len != WA_AES_256) {
        return NULL;
    }

    k = malloc(sizeof(WEBAUTH_KEY));
    if (k == NULL) {
        return NULL;
    }

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

WEBAUTH_KEY *
webauth_key_copy(const WEBAUTH_KEY *key) 
{
    WEBAUTH_KEY *copy;

    assert(key != NULL);
    assert(key->data != NULL);

    copy = malloc(sizeof(WEBAUTH_KEY));
    if (copy==NULL) {
        return NULL;
    }

    copy->type = key->type;
    copy->length = key->length;
    copy->data = malloc(copy->length);

    memcpy(copy->data, key->data, copy->length);
    return copy;
}

void
webauth_key_free(WEBAUTH_KEY *key) 
{
    assert(key != NULL);
    memset(key->data, 0, key->length);
    free(key->data);
    free(key);
}

WEBAUTH_KEYRING *
webauth_keyring_new(int initial_capacity)
{
    WEBAUTH_KEYRING *ring;

    /* Make sure the initial capacity is at least 1, since otherwise we try
       to malloc 0 bytes of memory, often returning NULL. */
    if (initial_capacity < 1)
        initial_capacity = 1;

    ring = malloc(sizeof(WEBAUTH_KEYRING));
    if (ring != NULL) {
        ring->num_entries = 0;
        ring->capacity = initial_capacity;
        ring->entries = 
            malloc(sizeof(WEBAUTH_KEYRING_ENTRY)*initial_capacity);
        if (ring->entries == NULL) {
            free(ring);
            return NULL;
        }
    }
    return ring;
}

void
webauth_keyring_free(WEBAUTH_KEYRING *ring)
{
    int i;

    assert(ring);

    /* free all the keys first */
    for (i=0; i < ring->num_entries; i++) {
        webauth_key_free(ring->entries[i].key);
    }
    /* free the entries array */
    free(ring->entries);
    /* free the ring */
    free(ring);
}

int
webauth_keyring_add(WEBAUTH_KEYRING *ring, 
                     time_t creation_time,
                     time_t valid_after,
                     WEBAUTH_KEY *key)
{
    assert(ring);
    assert(key);

    if (ring->num_entries == ring->capacity) {
        int new_capacity = ring->capacity *2;
        int new_size = sizeof(WEBAUTH_KEYRING_ENTRY) * new_capacity;
        WEBAUTH_KEYRING_ENTRY *new_entries = 
            (WEBAUTH_KEYRING_ENTRY*) realloc(ring->entries, new_size);
        if (new_entries == NULL) {
            return WA_ERR_NO_MEM;
        }
        ring->capacity = new_capacity;
        if (ring->entries != new_entries) {
            ring->entries = new_entries;
        }
    }

    if (creation_time == 0 || valid_after == 0) {
        time_t curr = time(NULL);
        if (creation_time == 0) {
            creation_time = curr;
        }
        if (valid_after == 0) {
            valid_after = curr;
        }
    }
    ring->entries[ring->num_entries].creation_time = creation_time;
    ring->entries[ring->num_entries].valid_after = valid_after;
    ring->entries[ring->num_entries].key = webauth_key_copy(key);
    if (ring->entries[ring->num_entries].key == NULL) {
        return WA_ERR_NO_MEM;
    }
    ring->num_entries++;
    return WA_ERR_NONE;
}

int
webauth_keyring_remove(WEBAUTH_KEYRING *ring, int index)
{
    int i;

    assert(ring);

    if (index < 0 || index >= ring->num_entries) {
        return WA_ERR_NOT_FOUND;
    }

    /* free the key */
    webauth_key_free(ring->entries[index].key);

    /* shift everyone down one */
    for (i = index+1; i < ring->num_entries; i++) {
        ring->entries[i-1] = ring->entries[i];
    }

    ring->num_entries--;
    return WA_ERR_NONE;
}

WEBAUTH_KEY *
webauth_keyring_best_key(const WEBAUTH_KEYRING *ring,
                         int encryption,
                         time_t hint)
{
    int i;
    time_t curr;
    WEBAUTH_KEYRING_ENTRY *b, *e;

    assert(ring);

    time(&curr);

    if (ring->num_entries == 0) {
        return NULL;
    }

    b = NULL;
    for (i=0; i < ring->num_entries; i++) {
        e = &ring->entries[i];
        if (encryption) {
            /* skip post-dated keys */
            if (e->valid_after > curr) {
                continue;
            }
            if (b == NULL || e->valid_after > b->valid_after) {
                b = e;
            }
        } else {
            /* skip post-dated keys */
            if (e->valid_after > curr) {
                continue;
            }
            if ((b == NULL) || 
                (hint >= e->valid_after && e->valid_after >= b->valid_after)) {
                b = e;
            }
        }
    }
    return  (b != NULL) ? b->key : NULL;
}

static int
read_fully(int fd, unsigned char *buff, int n)
{
    int tot=0, num_read;
    
    while (tot != n) {
        num_read = read(fd, buff+tot, n-tot);
        if (num_read < 0) {
            if (errno != EINTR) {
                return tot;
            }
        } else {
            tot += num_read;
        }
    }
    return tot;
}


#define KEYRING_VERSION 1

/*
 * 
 * format of keyring file, bunch of attrs.
 * 
 * v={version}           uiunt32_t
 * n={num-entries}       uint32_t
 * ct%d={creation-time}  time_t
 * vf%d={valid-after}     time_t
 * kt%d={key-type}       uint32_t
 * key%d={key-data}      binary-data
 * 
 */

#define A_VERSION "v"
#define A_NUM_ENTRIES "n"
#define A_CREATION_TIME "ct%d"
#define A_VALID_AFTER "va%d"
#define A_KEY_TYPE "kt%d"
#define A_KEY_DATA "kd%d"

int 
webauth_keyring_encode(WEBAUTH_KEYRING *ring, 
                       unsigned char **buffer,
                       int *buffer_len)
{
    int i, attr_len;
    WEBAUTH_ATTR_LIST *alist;
    int status;
    char name[32];

    assert(ring);
    assert(buffer);
    assert(buffer_len);

    *buffer = NULL;
    alist = NULL;

    alist = webauth_attr_list_new(ring->num_entries*5+2);
    if (alist == NULL) {
        status = WA_ERR_NO_MEM;
        goto cleanup;
    }

    status = webauth_attr_list_add_uint32(alist, A_VERSION,
                                          KEYRING_VERSION, WA_F_FMT_STR);
    if (status != WA_ERR_NONE)
        goto cleanup;

    status = webauth_attr_list_add_uint32(alist, A_NUM_ENTRIES,
                                          ring->num_entries, 
                                          WA_F_FMT_STR);
    if (status != WA_ERR_NONE)
        goto cleanup;

    for (i=0; i < ring->num_entries; i++) {
        sprintf(name, A_CREATION_TIME, i);
        status = webauth_attr_list_add_time(alist, name, 
                                            ring->entries[i].creation_time,
                                            WA_F_COPY_NAME|WA_F_FMT_STR);
        if (status != WA_ERR_NONE)
            goto cleanup;

        sprintf(name, A_VALID_AFTER, i);
        status = webauth_attr_list_add_time(alist, name, 
                                            ring->entries[i].valid_after,
                                            WA_F_COPY_NAME|WA_F_FMT_STR);
        if (status != WA_ERR_NONE)
            goto cleanup;

        sprintf(name, A_KEY_TYPE, i);
        status = webauth_attr_list_add_uint32(alist, name, 
                                              ring->entries[i].key->type,
                                              WA_F_COPY_NAME|WA_F_FMT_STR);
        if (status != WA_ERR_NONE)
            goto cleanup;

        sprintf(name, A_KEY_DATA, i);
        status = webauth_attr_list_add(alist, name, 
                                       ring->entries[i].key->data,
                                       ring->entries[i].key->length,
                                       WA_F_COPY_BOTH|WA_F_FMT_HEX);
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

int 
webauth_keyring_write_file(WEBAUTH_KEYRING *ring, const char *path)
{
    int fd, attr_len;
    unsigned char *attr_buff;
    int status, retry;
    char *temp;

    assert(ring);

    attr_buff = NULL;
    temp = NULL;
    fd = -1;

    temp = malloc(strlen(path)+7+1); /* .XXXXXX\0 */
    if (temp == NULL)
        return WA_ERR_NO_MEM;


    retry = 0;
    fd = -1;
    while ((fd == -1) && (retry++ < 10)) {
        sprintf(temp, "%s.XXXXXX", path);
        mktemp(temp);

        fd = open(temp, O_WRONLY|O_TRUNC|O_CREAT|O_EXCL, 0600);

        if ((fd == -1) && (errno != EEXIST)) {
            status = WA_ERR_KEYRING_OPENWRITE;
            goto cleanup;
        }
    }

    status = webauth_keyring_encode(ring, &attr_buff, &attr_len);
    if (status != WA_ERR_NONE)
        goto cleanup;

    if (write(fd, attr_buff, attr_len) != attr_len) {
        status = WA_ERR_KEYRING_WRITE;
        goto cleanup;
    }

    if (close(fd) != 0) {
        status = WA_ERR_KEYRING_WRITE;
        goto cleanup;
    } else {
        fd = -1;
    }

    if (rename(temp, path) != 0) {
        status = WA_ERR_KEYRING_WRITE;
        goto cleanup;
    }

    status = WA_ERR_NONE;

 cleanup:

    if (attr_buff != NULL)
        free(attr_buff);

    /* should be -1 and closed by now, else an error occured */
    if (fd != -1) {
        close(fd);
        unlink(temp);
    }

    if (temp != NULL)
        free(temp);

    return status;

}

int
webauth_keyring_decode(unsigned char *buffer, int buffer_len,
                       WEBAUTH_KEYRING **ring)
{
    int i, s;
    uint32_t version, num_entries;
    WEBAUTH_ATTR_LIST *alist;
    unsigned char *key_data;
    int key_len;

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

    s = webauth_attr_list_get_uint32(alist, A_NUM_ENTRIES, 
                                     &num_entries, WA_F_FMT_STR);
    if (s != WA_ERR_NONE)
        goto cleanup;

    *ring = webauth_keyring_new(num_entries);

    if (*ring == NULL) {
        s = WA_ERR_NO_MEM;
        goto cleanup;
    }

    for (i=0; i < num_entries; i++) {
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
        s = webauth_attr_list_get(alist, name,
                                  (void*)&key_data, &key_len, 
                                  WA_F_FMT_HEX);
        if (s != WA_ERR_NONE)
            goto cleanup;

        key = webauth_key_create(key_type, key_data, key_len);

        if (key == NULL) {
            s = WA_ERR_NO_MEM;
            goto cleanup;
        }

        webauth_keyring_add(*ring,
                             (time_t)creation_time,
                             (time_t)valid_after, 
                             key);
        webauth_key_free(key);
    }

 cleanup:

    if (alist != NULL)
        webauth_attr_list_free(alist);

    if (s != WA_ERR_NONE && *ring != NULL) 
        webauth_keyring_free(*ring);

    return s;

}

int
webauth_keyring_read_file(const char *path, WEBAUTH_KEYRING **ring)
{
    int fd, n, len, s;
    struct stat sbuf;
    unsigned char *buff;

    *ring = NULL;
    buff = NULL;
    fd = -1;

    /* FIXME: locking */
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
    if (n != len) {
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

static int
new_ring(const char *path, WEBAUTH_KEYRING **ring)
{
    WEBAUTH_KEY *key;
    unsigned char key_material[WA_AES_128];
    int s;
    time_t curr = time(NULL);
    key = NULL;

    /* create new key ring */
    *ring = webauth_keyring_new(5);
    if (*ring == NULL) {
        s =WA_ERR_NO_MEM;
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



static int
check_ring(const char *path, int lifetime, 
           WEBAUTH_KEYRING *ring, 
           WEBAUTH_KAU_STATUS *updated)
{
    time_t curr;
    WEBAUTH_KEY *key;
    int s, i;
    unsigned char key_material[WA_AES_128];

    time(&curr);

    /* see if we have at least one key whose valid_after+lifetime is
       still greater then current time */
    for (i=0; i < ring->num_entries; i++) {
        if (ring->entries[i].valid_after+lifetime > curr) {
            /* nothing to do */
            return WA_ERR_NONE;
        }
    }

    *updated = WA_KAU_UPDATE;

    /* lets add a new key to the key ring and write it out */

    s = webauth_random_key(key_material, WA_AES_128);
    if (s != WA_ERR_NONE)
        return s;

    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);

    if (key == NULL) {
        return WA_ERR_NO_MEM;
    }

    s = webauth_keyring_add(ring, curr, curr, key);
    if (s != WA_ERR_NONE) {
        webauth_key_free(key);
        return s;
    }

    webauth_key_free(key);

    return webauth_keyring_write_file(ring, path);
}



int 
webauth_keyring_auto_update(const char *path, 
                            int create,
                            int lifetime,
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
        if (!create) {
            return s;
        } else {
            *updated = WA_KAU_CREATE;
            return new_ring(path, ring);
        }
    }

    if (lifetime)
        *update_status = check_ring(path, lifetime, *ring, updated);
    return s;
}

/*
**  Local variables:
**  mode: c
**  c-basic-offset: 4
**  indent-tabs-mode: nil
**  end:
*/
