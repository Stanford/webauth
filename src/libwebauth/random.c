#include <openssl/rand.h>

#include "webauthp.h"

int webauth_random_bytes(unsigned char *output, int num_bytes)
{
    int s;
    /* XXX: leave as assert for now, later, need to handle
       case where /dev/random doesn't exist */
    assert(RAND_status());
    s = RAND_pseudo_bytes(output, num_bytes);
    return (s==-1) ? WA_ERR_RAND_FAILURE : WA_ERR_NONE;
}

int webauth_random_key(unsigned char *key, int key_len)
{
    int s;
    /* XXX: leave as assert for now, later, need to handle
       case where /dev/random doesn't exist */
    assert(RAND_status());
    s = RAND_bytes(key, key_len);
    return (s==1) ?WA_ERR_NONE : WA_ERR_RAND_FAILURE;
}

