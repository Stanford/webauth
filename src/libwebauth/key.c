#include "webauthp.h"

#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>
#include <inttypes.h>

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

WEBAUTH_KEY_RING *
webauth_key_ring_new(int initial_capacity)
{
    WEBAUTH_KEY_RING *ring;

    ring = malloc(sizeof(WEBAUTH_KEY_RING));
    if (ring != NULL) {
        ring->version = 1;
        ring->num_entries = 0;
        ring->capacity = initial_capacity;
        ring->entries = 
            malloc(sizeof(WEBAUTH_KEY_RING_ENTRY)*initial_capacity);
        if (ring->entries == NULL) {
            free(ring);
            return NULL;
        }
    }
    return ring;
}

void
webauth_key_ring_free(WEBAUTH_KEY_RING *ring)
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
webauth_key_ring_add(WEBAUTH_KEY_RING *ring, 
                     time_t creation_time,
                     time_t valid_from,
                     time_t valid_till,
                     WEBAUTH_KEY *key)
{
    assert(ring);
    assert(key);

    if (ring->num_entries == ring->capacity) {
        int new_capacity = ring->capacity *2;
        int new_size = sizeof(WEBAUTH_KEY_RING_ENTRY) * new_capacity;
        WEBAUTH_KEY_RING_ENTRY *new_entries = 
            (WEBAUTH_KEY_RING_ENTRY*) realloc(ring->entries, new_size);
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
webauth_key_ring_best_encryption_key(const WEBAUTH_KEY_RING *ring)
{
    int i;
    time_t curr;
    WEBAUTH_KEY_RING_ENTRY *b, *e;

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

WEBAUTH_KEY_RING *webauth_key_ring_read_file(char *filename);
int webauth_key_ring_write_file(char *filename);

/*
**  Local variables:
**  mode: c
**  c-basic-offset: 4
**  indent-tabs-mode: nil
**  end:
*/
