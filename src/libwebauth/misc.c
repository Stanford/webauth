#include "webauthp.h"

#include <ctype.h>

static char hex[] = "0123456789abcdef";


const char *
webauth_error_message(int errcode)
{
#define EM(c,m) case c: return m; break
    switch(errcode) {
        EM(WA_ERR_NONE,    "No error occurred");
        EM(WA_ERR_NO_ROOM, "Supplied buffer too small");
        EM(WA_ERR_CORRUPT, "Data is incorrectly formatted");
        EM(WA_ERR_NO_MEM,  "No memory");
        EM(WA_ERR_BAD_HMAC, "HMAC check failed");
        EM(WA_ERR_RAND_FAILURE, "Unable to get random data");
        EM(WA_ERR_BAD_KEY,  "Unable to use key");
        EM(WA_ERR_KEYRING_OPENWRITE, "Unable to open keyring for writing");
        EM(WA_ERR_KEYRING_WRITE, "Error writing key ring");
        EM(WA_ERR_KEYRING_OPENREAD, "Unable to open keyring for reading");
        EM(WA_ERR_KEYRING_READ, "Error reading from keyring file");
        EM(WA_ERR_KEYRING_VERSION,  "Bad keyring version");
        EM(WA_ERR_NOT_FOUND, "Item not found while searching");
        EM(WA_ERR_KRB5, "Kerberos V5 error");
        EM(WA_ERR_INVALID_CONTEXT, "Invalid context passed to function");
        EM(WA_ERR_LOGIN_FAILED, "Login failed (bad username/password)");
        EM(WA_ERR_TOKEN_EXPIRED, "Token has expired");
        EM(WA_ERR_TOKEN_STALE, "Token is stale");
        default:
            return "unknown error code";
            break;
    }
#undef EM
}


int
webauth_hex_encoded_length(int length)
{
    return length*2;
}


int
webauth_hex_decoded_length(int length, int *out_length)
{
    if (length%2) {
        *out_length = 0;
        return WA_ERR_CORRUPT;
    } else {
        *out_length = length/2;
        return WA_ERR_NONE;
    }
}


int
webauth_hex_encode(unsigned char *input, 
                   int input_len,
                   unsigned char *output,
                   int *output_len,
                   int max_output_len)
{
    int out_len;
    unsigned char *s;
    unsigned char *d;

    *output_len = 0;
    out_len = 2*input_len;
    s = input+input_len-1;
    d = output+out_len-1;

    if (max_output_len < out_len) {
	return WA_ERR_NO_ROOM;
    }

    while (input_len) {
	*d-- = hex[*s & 15];
	*d-- = hex[*s-- >> 4];
	input_len--;
    }

    *output_len = out_len;
    return WA_ERR_NONE;
}

#define hex2int(c)\
(isdigit(c) ? (c- '0') : ((c >= 'A' && c <= 'F') ? (c-'A'+10) : (c-'a'+10)))

int
webauth_hex_decode(unsigned char *input,
                   int input_len,
                   unsigned char *output, 
                   int *output_len,
                   int max_output_len)
{
    unsigned char *s = input;
    unsigned char *d = output;
    int n;

    assert(input != NULL);
    assert(output != NULL);
    assert(output_len != NULL);

    *output_len = 0;

    if (input_len == 0) {
	if (max_output_len > 0) {
	    return WA_ERR_NONE;
	} else {
	    return WA_ERR_NO_ROOM;
	}
    }

    if (input_len %2 != 0) {
	return WA_ERR_CORRUPT;
    }

    if (max_output_len < (input_len/2)) {
	return WA_ERR_NO_ROOM;
    }

    n = input_len;
    while (n) {
	if (isxdigit(*s) && isxdigit(*(s+1))) {
	    *d++ = (unsigned char)((hex2int(*s) << 4) + hex2int(*(s+1)));
	    s += 2;
            n -= 2;
	} else {
	    return WA_ERR_CORRUPT;
	}
    }
    *output_len = input_len/2;

    return WA_ERR_NONE;
}

/*
**  Local variables:
**  mode: c
**  c-basic-offset: 4
**  indent-tabs-mode: nil
**  end:
*/
