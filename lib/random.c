/*
 * Random data generation functions.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2006, 2009
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include "webauthp.h"

#include <openssl/rand.h>

int
webauth_random_bytes(char *output, int num_bytes)
{
    int s;
    /* FIXME: leave as assert for now, later, need to handle
       case where rand initialization fails. Also have abort
       in case assert is not compiled in */
    s = RAND_status();
    assert(s == 1);
    if (s != 1) {
        abort();
    }
    s = RAND_pseudo_bytes((unsigned char *) output, num_bytes);
    return (s == -1) ? WA_ERR_RAND_FAILURE : WA_ERR_NONE;
}

int
webauth_random_key(char *key, int key_len)
{
    int s;
    /* FIXME: leave as assert for now, later, need to handle
       case where rand initialization fails. Also have abort
       in case assert is not compiled in */
    s = RAND_status();
    assert(s == 1);
    if (s != 1) {
        abort();
    }
    s = RAND_bytes((unsigned char *) key, key_len);
    return (s==1) ?WA_ERR_NONE : WA_ERR_RAND_FAILURE;
}

/*
**  Local variables:
**  mode: c
**  c-basic-offset: 4
**  indent-tabs-mode: nil
**  end:
*/
