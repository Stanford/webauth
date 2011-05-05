/*
 * Test suite for libwebauth random number generation functions.
 *
 * Written by Roland Schemers
 * Updated for current TAP library support by Russ Allbery
 * Copyright 2002, 2003, 2006, 2009, 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lib/webauth.h>
#include <tests/tap/basic.h>

#define BUFSIZE 2048


int
main(void)
{
    char orig_buffer[BUFSIZE];
    int s;

    plan(2);

    s = webauth_random_key(orig_buffer, WA_AES_128);
    is_int(WA_ERR_NONE, s, "Getting a 128-bit random key succeeds");
    s = webauth_random_bytes(orig_buffer, 32);
    is_int(WA_ERR_NONE, s, "Getting 32 random bytes succeeds");

    return 0;
}
