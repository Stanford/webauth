/*
 * Test suite for libwebauth hex encoding and decoding.
 *
 * Written by Roland Schemers
 * Updated for current TAP library support by Russ Allbery
 * Copyright 2002, 2003, 2006, 2009, 2010, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lib/internal.h>
#include <tests/tap/basic.h>
#include <webauth/basic.h>

#define BUFSIZE 2048


int
main(void)
{
    char orig_buffer[BUFSIZE];
    char encoded_buffer[BUFSIZE];
    char decoded_buffer[BUFSIZE];
    size_t i, j;
    int s;
    size_t elen, rlen, dlen, dlen2;

    plan(7 * 512);

    for (i = 0; i < 512; i++) {
        for (j = 0; j < i; j++)
            orig_buffer[j] = j % 256;
        s = wai_hex_encode(orig_buffer, i, encoded_buffer, &elen, BUFSIZE);
        rlen = wai_hex_encoded_length(i);
        is_int(WA_ERR_NONE, s, "Encoding length %lu succeeds",
                (unsigned long) i);
        is_int(rlen, elen, "...and returns the correct length");

        s = wai_hex_decode(encoded_buffer, elen, decoded_buffer, &dlen,
                           BUFSIZE);
        is_int(WA_ERR_NONE, s, "Decoding length %lu succeeds",
                (unsigned long) i);
        s = wai_hex_decoded_length(elen, &dlen2);
        is_int(WA_ERR_NONE, s, "Determing the decoded length succeeds");
        is_int(dlen, dlen2, "...and the lengths match");
        is_int(i, dlen, "...and match the original length");
        ok(memcmp(decoded_buffer, orig_buffer, i) == 0, "...and data");
    }

    return 0;
}
