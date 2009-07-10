/*
 * Random data generation functions.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2006, 2009
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <lib/webauthp.h>

#include <openssl/rand.h>

/*
 * Generate num_bytes random bytes and store them in output.  This is
 * currently a simple wrapper around the OpenSSL function.
 */
int
webauth_random_bytes(char *output, int num_bytes)
{
    int s;

    /*
     * The abort is in case assert is not compiled in.  FIXME: need to handle
     * case where rand initialization fails.
     */
    s = RAND_status();
    assert(s == 1);
    if (s != 1)
        abort();
    s = RAND_pseudo_bytes((unsigned char *) output, num_bytes);
    return (s == -1) ? WA_ERR_RAND_FAILURE : WA_ERR_NONE;
}


/*
 * Generate a random WebAuth key.  This is currently exactly the same function
 * as webauth_random_bytes.
 */
int
webauth_random_key(char *key, int key_len)
{
    int s;

    /*
     * The abort is in case assert is not compiled in.  FIXME: need to handle
     * case where rand initialization fails.
     */
    s = RAND_status();
    assert(s == 1);
    if (s != 1)
        abort();
    s = RAND_bytes((unsigned char *) key, key_len);
    return (s == 1) ?WA_ERR_NONE : WA_ERR_RAND_FAILURE;
}
