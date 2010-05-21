/*
 * General WebAuth utility functions.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2009 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <lib/webauthp.h>

#include <ctype.h>

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
 * Map an error code to an error message.  Returns a constant string.
 */
const char *
webauth_error_message(int errcode)
{
    switch(errcode) {
    case WA_ERR_NONE:              return "No error occurred";
    case WA_ERR_NO_ROOM:           return "Supplied buffer too small";
    case WA_ERR_CORRUPT:           return "Data is incorrectly formatted";
    case WA_ERR_NO_MEM:            return "No memory";
    case WA_ERR_BAD_HMAC:          return "HMAC check failed";
    case WA_ERR_RAND_FAILURE:      return "Unable to get random data";
    case WA_ERR_BAD_KEY:           return "Unable to use key";
    case WA_ERR_KEYRING_OPENWRITE: return "Unable to open keyring for writing";
    case WA_ERR_KEYRING_WRITE:     return "Error writing key ring";
    case WA_ERR_KEYRING_OPENREAD:  return "Unable to open keyring for reading";
    case WA_ERR_KEYRING_READ:      return "Error reading from keyring file";
    case WA_ERR_KEYRING_VERSION:   return "Bad keyring version";
    case WA_ERR_NOT_FOUND:         return "Item not found while searching";
    case WA_ERR_KRB5:              return "Kerberos V5 error";
    case WA_ERR_INVALID_CONTEXT:   return "Invalid context passed to function";
    case WA_ERR_LOGIN_FAILED:      return "Login failed (bad username/password";
    case WA_ERR_TOKEN_EXPIRED:     return "Token has expired";
    case WA_ERR_TOKEN_STALE:       return "Token is stale";
    case WA_ERR_CREDS_EXPIRED:     return "Password has expired";
    default:
        return "unknown error code";
        break;
    }
}


/*
 * Return the build information for this copy of WebAuth.
 */
const char *
webauth_info_build(void)
{
    return PACKAGE_BUILD_INFO;
}


/*
 * Return the version of this build of WebAuth.
 */
const char *
webauth_info_version(void)
{
    return PACKAGE_VERSION;
}


/*
 * Given the length of data, return the length required to store that data
 * encoded in hex.
 */
int
webauth_hex_encoded_length(int length)
{
    return length * 2;
}


/*
 * Given the length of data encoded in hex, return the space required to store
 * the decoded data.
 */
int
webauth_hex_decoded_length(int length, int *out_length)
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
webauth_hex_encode(char *input, int input_len, char *output, int *output_len,
                   int max_output_len)
{
    int out_len;
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
webauth_hex_decode(char *input, int input_len, char *output, int *output_len,
                   int max_output_len)
{
    unsigned char *s = (unsigned char *) input;
    unsigned char *d = (unsigned char *) output;
    int n;

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
