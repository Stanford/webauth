/*
 * Random data generation functions.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2006, 2009, 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <assert.h>
#include <openssl/rand.h>

#include <webauth.h>
#include <webauth/basic.h>


/*
 * Generate num_bytes random bytes and store them in output.  This is
 * currently a simple wrapper around the OpenSSL function.
 */
int
webauth_random_bytes(unsigned char *output, size_t num_bytes)
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
    s = RAND_pseudo_bytes(output, num_bytes);
    return (s == -1) ? WA_ERR_RAND_FAILURE : WA_ERR_NONE;
}


/*
 * Generate a random WebAuth key.  This is currently exactly the same function
 * as webauth_random_bytes.
 */
int
webauth_random_key(unsigned char *key, size_t key_len)
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
    s = RAND_bytes(key, key_len);
    return (s == 1) ?WA_ERR_NONE : WA_ERR_RAND_FAILURE;
}
