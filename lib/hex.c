/*
 * General WebAuth utility functions.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2009, 2010, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <assert.h>
#include <ctype.h>

#include <lib/internal.h>
#include <webauth/basic.h>

/*
 * Converts a hex digit to a number.   This macro will return non-sensical
 * results if given invalid hex digits.
 */
#define HEX2INT(c) \
    (isdigit(c) ? ((c) - '0') \
                : (((c) >= 'A' && (c) <= 'F') ? ((c) - 'A' + 10) \
                                              : ((c) - 'a' + 10)))

/* Used for hex encoding. */
static char hex[] = "0123456789abcdef";


/*
 * Given the length of data, return the length required to store that data
 * encoded in hex.
 */
size_t
wai_hex_encoded_length(size_t length)
{
    return length * 2;
}


/*
 * Given the length of data encoded in hex, return the space required to store
 * the decoded data.
 */
int
wai_hex_decoded_length(size_t length, size_t *out_length)
{
    if (length % 2) {
        *out_length = 0;
        return WA_ERR_CORRUPT;
    } else {
        *out_length = length / 2;
        return WA_ERR_NONE;
    }
}


/*
 * Given a buffer of data and its length, encode it into hex and store it in
 * the buffer pointed to by output.  Store the encoded length in output_len.
 * output must point to at least max_output_len bytes of space.  Returns a
 * WA_ERR code.
 */
int
wai_hex_encode(const char *input, size_t input_len, char *output,
               size_t *output_len, size_t max_output_len)
{
    size_t out_len;
    unsigned char *s;
    unsigned char *d;

    *output_len = 0;
    out_len = 2 * input_len;
    s = (unsigned char *) input + input_len - 1;
    d = (unsigned char *) output + out_len - 1;

    if (max_output_len < out_len)
        return WA_ERR_NO_ROOM;

    while (input_len) {
        *d-- = hex[*s & 15];
        *d-- = hex[*s-- >> 4];
        input_len--;
    }

    *output_len = out_len;
    return WA_ERR_NONE;
}


/*
 * Given a hex-encded string in input of length input_len, decode it into the
 * buffer pointed to by output and store the decoded length in output_len.
 * max_output_len is the size of the buffer.  Returns a WA_ERR code.
 */
int
wai_hex_decode(char *input, size_t input_len, char *output,
               size_t *output_len, size_t max_output_len)
{
    unsigned char *s = (unsigned char *) input;
    unsigned char *d = (unsigned char *) output;
    size_t n;

    assert(input != NULL);
    assert(output != NULL);
    assert(output_len != NULL);

    *output_len = 0;

    if (input_len == 0) {
        if (max_output_len > 0)
            return WA_ERR_NONE;
        else
            return WA_ERR_NO_ROOM;
    }
    if (input_len % 2 != 0)
        return WA_ERR_CORRUPT;
    if (max_output_len < (input_len / 2))
        return WA_ERR_NO_ROOM;

    n = input_len;
    while (n) {
        if (isxdigit(*s) && isxdigit(*(s + 1))) {
            *d++ = (unsigned char) ((HEX2INT(*s) << 4) + HEX2INT(*(s + 1)));
            s += 2;
            n -= 2;
        } else
            return WA_ERR_CORRUPT;
    }
    *output_len = input_len / 2;

    return WA_ERR_NONE;
}
