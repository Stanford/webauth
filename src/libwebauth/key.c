#include "webauthp.h"

/* FIXME: autoconf */
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>
#include <unistd.h>

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
                     time_t valid_from,
                     time_t valid_till,
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

    if (creation_time == 0 || valid_from == 0) {
        time_t curr = time(NULL);
        if (creation_time == 0) {
            creation_time = curr;
        }
        if (valid_from == 0) {
            valid_from = curr;
        }
    }
    ring->entries[ring->num_entries].creation_time = creation_time;
    ring->entries[ring->num_entries].valid_from = valid_from;
    ring->entries[ring->num_entries].valid_till = valid_till;
    ring->entries[ring->num_entries].key = key;
    ring->num_entries++;
    return WA_ERR_NONE;
}

WEBAUTH_KEY *
webauth_keyring_best_encryption_key(const WEBAUTH_KEYRING *ring)
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
        /* skip post-dated keys and skip expired-keys */
        if (e->valid_from > curr ||e->valid_till < curr) {
            continue;
        }
        if (b == NULL || b->valid_till > b->valid_till) {
            b = e;
        }
    }
    return  b ? b->key : NULL;
}

#define KEYRING_VERSION 1

/*
 * 
 * format of keyring file:
 *
 * {version}         uint32_t (network byte order)
 * {num_entries}       "           "
 * {entry1-length}     "           "
 * {entry1-attrs}
 * {entry2-length}
 * {entry2-attrs}
 * ...
 * 
 * each entryN-attrs is an attr-coded buffer containing the following attrs:
 *
 *  creation_time    uint32_t (network byte order)
 *  valid_from       uint32_t (network byte order)
 *  valid_till       uint32_t (network byte order)
 *  key_type         uint32_t (network byte order)
 *  key_data         binary key data
 * 
 */

int 
webauth_keyring_write_file(WEBAUTH_KEYRING *ring, char *path)
{
    uint32_t temp, creation_time, valid_from, valid_till, key_type;
    int fd, i, attr_len, len;
    WEBAUTH_ATTR_LIST *attrs;
    unsigned char *attr_buff;
    int status;

    assert(ring);

    status = WA_ERR_NONE;

    /* FIXME: locking */
    /* FIXME: when we have logging support, should log errors */
    fd = open(path, O_WRONLY|O_TRUNC|O_CREAT, 0600);
    if (fd == -1) {
        return WA_ERR_KEYRING_WRITE;
    }

    /* version first */
    temp = htonl(KEYRING_VERSION); 
    if (write(fd, &temp, sizeof(temp)) != sizeof(temp)) {
        close(fd);
        return WA_ERR_KEYRING_WRITE;
    }

    /* num_entries next */
    temp = htonl(ring->num_entries); 
    if (write(fd, &temp, sizeof(temp)) != sizeof(temp)) {
        close(fd);
        return WA_ERR_KEYRING_WRITE;
    }

    attrs = webauth_attr_list_new(32);

    if (attrs == NULL) {
        close(fd);
        return WA_ERR_NO_MEM;
    }

    /* entries next */
    attr_buff = NULL;
    for (i=0; status==WA_ERR_NONE && i < ring->num_entries; i++) {
        attrs->num_attrs = 0;
        creation_time = htonl(ring->entries[i].creation_time);
        valid_from = htonl(ring->entries[i].valid_from);
        valid_till = htonl(ring->entries[i].valid_till);
        key_type   = htonl(ring->entries[i].key->type);
 
        webauth_attr_list_add(attrs, "creation_time", &creation_time, 
                              sizeof(creation_time));
        webauth_attr_list_add(attrs, "valid_from", &valid_from,
                              sizeof(valid_from));
        webauth_attr_list_add(attrs, "valid_till", &valid_till,
                              sizeof(valid_till));
        webauth_attr_list_add(attrs, "key_type", &key_type,
                              sizeof(key_type));
        webauth_attr_list_add(attrs, "key_data", ring->entries[i].key->data,
                              ring->entries[i].key->length);

        attr_len = webauth_attrs_encoded_length(attrs);
        attr_buff = realloc(attr_buff, attr_len > 2048 ? attr_len : 2048);
        len = webauth_attrs_encode(attrs, attr_buff, attr_len);

        if (len < 0) {
            status = len;
        }

        /* write encoded entry length */
        temp = htonl(attr_len);
        if (!status && write(fd, &temp, sizeof(temp)) != sizeof(temp)) {
            status = WA_ERR_KEYRING_WRITE;
        }

        /* followed by encoded entry */
        if (!status && (write(fd, attr_buff, attr_len) != attr_len)) {
            status = WA_ERR_KEYRING_WRITE;
        }
    }

    close(fd);
    if (attr_buff) {
        free(attr_buff);
    }
    webauth_attr_list_free(attrs);
    return status;

}

static int
read_fully(int fd, char *buff, int n)
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

static int
get_uint32_t(WEBAUTH_ATTR_LIST *list, char *name, uint32_t *v)
{
    int index = webauth_attr_list_find(list, name);

    if (index < 0) {
        return index;
    }

    if (list->attrs[index].length != sizeof(uint32_t)) {
        return WA_ERR_CORRUPT;
    }

    memcpy(v, list->attrs[index].value, sizeof(uint32_t));

    *v = ntohl(*v);

    return WA_ERR_NONE;
}

int
webauth_keyring_read_file(char *path, WEBAUTH_KEYRING **ring)
{
    int fd, n, len, i, s;
    struct stat sbuf;
    char *buff, *p;
    uint32_t version, num_entries;

    /* FIXME: locking */
    /* FIXME: when we have logging support, should log errors */

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return WA_ERR_KEYRING_READ;
    }

    if (fstat(fd, &sbuf) < 0) {
        close(fd);
        return WA_ERR_KEYRING_READ;
    }

    len = sbuf.st_size;

    buff = malloc(len);
    if (buff == NULL) {
        close(fd);
        return WA_ERR_NO_MEM;
    }

    n = read_fully(fd, buff, len);
    if (n != len) {
        close(fd);
        free(buff);
        return WA_ERR_KEYRING_READ;
    }
    close(fd);

    if (len < sizeof(version)) {
        free(buff);
        return WA_ERR_CORRUPT;
    }

    p = buff;

    memcpy(&version, p, sizeof(version));
    p += sizeof(version);
    len -= sizeof(version);

    version = ntohl(version);

    if (version != KEYRING_VERSION) {
        free(buff);
        return WA_ERR_KEYRING_VERSION;
    }

    if (len < sizeof(num_entries)) {
        free(buff);
        return WA_ERR_CORRUPT;
    }

    memcpy(&num_entries, p, sizeof(num_entries));
    p += sizeof(num_entries);
    len -= sizeof(num_entries);

    num_entries = ntohl(num_entries);

    *ring = webauth_keyring_new(num_entries);

    if (*ring == NULL) {
        free(buff);
        return WA_ERR_NO_MEM;
    }

    for (i=0; i < num_entries; i++) {
        uint32_t creation_time, valid_from, valid_till, key_type;
        uint32_t entry_length;
        int key_data_index = WA_ERR_NOT_FOUND;
        WEBAUTH_ATTR_LIST *list;
        WEBAUTH_KEY *key;

        if (len < sizeof(entry_length)) {
            free(buff);
            webauth_keyring_free(*ring);
            return WA_ERR_CORRUPT;
        }

        memcpy(&entry_length, p, sizeof(entry_length));
        p += sizeof(entry_length);
        len -= sizeof(entry_length);

        entry_length = ntohl(entry_length);

        if (len < entry_length) {
            free(buff);
            webauth_keyring_free(*ring);
            return WA_ERR_CORRUPT;
        }

        s = webauth_attrs_decode(p, entry_length, &list);
        if (s <0) {
            free(buff);
            webauth_keyring_free(*ring);
            return s;
        }

        s = get_uint32_t(list, "creation_time", &creation_time);
        if (s == WA_ERR_NONE) {
            s = get_uint32_t(list, "valid_from", &valid_from);
        }
        if (s == WA_ERR_NONE) {
            s = get_uint32_t(list, "valid_till", &valid_till);
        }
        if (s == WA_ERR_NONE) {
            s = get_uint32_t(list, "key_type", &key_type);
        }

        if (s == WA_ERR_NONE) {
            key_data_index = webauth_attr_list_find(list, "key_data");
            if (key_data_index < 0) {
                s = key_data_index;
            }
        }

        if (s != WA_ERR_NONE) {
            free(buff);
            webauth_keyring_free(*ring);
            webauth_attr_list_free(list);
            return s;
        }


        key = webauth_key_create(key_type, list->attrs[key_data_index].value,
                                 list->attrs[key_data_index].length);

        if (key == NULL) {
            free(buff);
            webauth_keyring_free(*ring);
            webauth_attr_list_free(list);
        }

        webauth_keyring_add(*ring,
                             (time_t)creation_time,
                             (time_t)valid_from, 
                             (time_t)valid_till,
                             key);
        webauth_attr_list_free(list);
        p += entry_length;
        len -= entry_length;
    }

    free(buff);
    return WA_ERR_NONE;
}

/*
**  Local variables:
**  mode: c
**  c-basic-offset: 4
**  indent-tabs-mode: nil
**  end:
*/
