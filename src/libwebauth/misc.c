#include "webauthp.h"

/* XXX: autoconf */
#include <ctype.h>

static char hex[] = "0123456789abcdef";


int webauth_hex_encoded_length(int length)
{
    return length*2;
}


int webauth_hex_encode(unsigned char *input, 
                       int input_len,
                       unsigned char *output,
                       int max_output_len)
{
    int out_len;
    unsigned char *s;
    unsigned char *d;

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

    return out_len;
}

#define hex2int(c)\
(isdigit(c) ? (c- '0') : ((c >= 'A' && c <= 'F') ? (c-'A'+10) : (c-'a'+10)))

int webauth_hex_decode(unsigned char *input,
                       int input_len,
                       unsigned char *output, 
                       int max_output_len)
{
    unsigned char *s = input;
    unsigned char *d = output;
    int out_len = input_len/2;

    if (input_len == 0) {
	if (max_output_len > 0) {
	    return 0;
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

    while (input_len) {
	if (isxdigit(*s) && isxdigit(*(s+1))) {
	    *d++ = (unsigned char)((hex2int(*s) << 4) + hex2int(*(s+1)));
	    s += 2;
            input_len -= 2;
	} else {
	    return WA_ERR_CORRUPT;
	}
    }
    return out_len;
}
