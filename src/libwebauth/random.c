#include <openssl/rand.h>

#include "webauthp.h"

int
webauth_random_bytes(unsigned char *output, int num_bytes)
{
    int s;
    /* FIXME: leave as assert for now, later, need to handle
       case where rand initialization fails. Also have abort
       in case assert is not compiled in */
    s = RAND_status();
    assert(s==1);
    if (s!=1) {
        abort();
    }
    s = RAND_pseudo_bytes(output, num_bytes);
    return (s==-1) ? WA_ERR_RAND_FAILURE : WA_ERR_NONE;
}

int
webauth_random_key(unsigned char *key, int key_len)
{
    int s;
    /* FIXME: leave as assert for now, later, need to handle
       case where rand initialization fails. Also have abort
       in case assert is not compiled in */
    s = RAND_status();
    assert(s==1);
    if (s!=1) {
        abort();
    }
    s = RAND_bytes(key, key_len);
    return (s==1) ?WA_ERR_NONE : WA_ERR_RAND_FAILURE;
}

/*
**  Local variables:
**  mode: c
**  c-basic-offset: 4
**  indent-tabs-mode: nil
**  end:
*/
