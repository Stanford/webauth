/*
 * Test suite for libwebauth base64 encoding and decoding.
 *
 * Written by Roland Schemers
 * Updated for current TAP library support by Russ Allbery
 * Copyright 2002, 2003, 2006, 2009, 2010
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lib/webauth.h>
#include <tests/tap/basic.h>

#define BUFSIZE 1024


int
main(void)
{
    char orig_buffer[BUFSIZE];
    char encoded_buffer[BUFSIZE];
    char decoded_buffer[BUFSIZE];
    int i,j;
    int elen, rlen, rdlen, dlen;
    int s;

    plan(7 * 511);

    for (i = 1; i < 512; i++) {
        for (j = 0; j < i; j++)
            orig_buffer[j] = j % 256;
        s = webauth_base64_encode(orig_buffer, i,
                                  encoded_buffer, &elen, BUFSIZE);
        rlen = webauth_base64_encoded_length(i);
        is_int(WA_ERR_NONE, s, "Encoding length %i succeeds", i);
        is_int(rlen, elen, "...and returns the correct length");

        s = webauth_base64_decoded_length(encoded_buffer, elen, &rdlen);
        is_int(WA_ERR_NONE, s, "Determining the decoded length succeeds");

        s = webauth_base64_decode(encoded_buffer, elen, 
                                  decoded_buffer, &dlen, BUFSIZE);
        is_int(WA_ERR_NONE, s, "Decoding length %i succeeds", i);
        is_int(rdlen, dlen, "...and returns the right length");
        is_int(i, dlen, "...which matches the original size");
        ok(memcmp(decoded_buffer, orig_buffer, i) == 0, "...and data");
    }

    return 0;
}
