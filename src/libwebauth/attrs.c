#include "webauthp.h"

/*
 * given an array of attributes, returns the amount
 * of space required to encode them.
 */

#define NAME_TERM '='
#define VAL_TERM ';'


int webauth_attrs_encoded_length(const WEBAUTH_ATTR *attrs, 
                                 int num_attrs)
{
    int space, i, len;
    unsigned char *p, *v;

    assert(attrs != NULL);
    assert(num_attrs > 0);

    space = 0;
    for (i=0; i < num_attrs; i++) {
        space += strlen(attrs[i].name) + 1;  /* +1 for NAME_TERM */
        v = attrs[i].value;
        len = attrs[i].length;
        while (len && (p = memchr(v, VAL_TERM, len))) {
            space++; /* add one for each VAL_TERM; we find */
            len -= p+1-v;
            v = p+1;
        } 
        space += attrs[i].length + 1; /* +1 for VAL_TERM */
    }
    return space;
}

/*
 * given an array of attributes, encode them into output.
 * The output buffer will dynamically be allocated if it
 * is NULL on input. If it is not NULL, then output_max must
 * be set to the maxium size of the output buffer.
 */

int webauth_attrs_encode(const WEBAUTH_ATTR *attrs, 
                         int num_attrs,
                         unsigned char *output,
                          int max_output_len)
{
   int i, len, slen, rlen;
   unsigned char *p, *v, *d;

    assert(attrs != NULL);
    assert(num_attrs > 0);
    assert(output != NULL);
 
   rlen = webauth_attrs_encoded_length(attrs, num_attrs);

   if (rlen > max_output_len) {
       return WA_ERR_NO_ROOM;
   }

    d = output;

    for (i=0; i < num_attrs; i++) {
        len = strlen(attrs[i].name);
        memcpy(d, attrs[i].name, len);
        d += len;
        *d++ = NAME_TERM;
        v = attrs[i].value;
        len = attrs[i].length;
        while (len && (p = memchr(v, VAL_TERM, len))) {
            slen = p-v+1;
            memcpy(d, v, slen);
            d += slen;
            *d++ = VAL_TERM; /* escape VAL_TERM */
            len -= slen;
            v = p+1;
        }
        /* copy leftover */
        if (len) {
            memcpy(d, v, len);
            d += len;
        }
        /* append VAL_TERM to value */
        *d++ = VAL_TERM;
    }
    return d - output;
}

/*
 * decodes the given buffer into an array of attributes.
 * The buffer is modifed, and the resulting names and
 * values in the attributes will point into the buffer.
 * All values will be null-terminated, for convenience
 * when dealing with values that are ASCII strings.
 */

int webauth_attrs_decode(unsigned char *buffer, 
                         int input_len,
                         WEBAUTH_ATTR *attrs,
                         int max_num_attrs)
{
    int n, i;
    int in_val;
    unsigned char *p, *d;

    assert(buffer != NULL);
    assert(input_len > 0);
    assert(attrs != NULL);
    assert(max_num_attrs > 0);

    n = 0;
    i = input_len;
    p = buffer;
    in_val = 0;

    while (i && n < max_num_attrs) {
        attrs[n].name = p;
        p++; 
        i--;
        while (i && *p != NAME_TERM) {
            p++;
            i--;
        }
        if (*p != NAME_TERM) {
            return WA_ERR_CORRUPT; /* no NAME_TERM found */
        }
        *p++ = '\0'; /* null terminate name */
        i--;
        if (!i) {
            return WA_ERR_CORRUPT; /* missing val term */
        }

        attrs[n].value = p;
        d = p;
        in_val = 1;

        while(i--) {
            if (*p != VAL_TERM) {
                if (d != p) {
                    *d = *p;
                }
            } else {
                if (!i || *(p+1) != VAL_TERM) {
                    /* end of value */
                    in_val = 0;
                    attrs[n].length = d - (unsigned char*)attrs[n].value;
                    *d++ = '\0';
                    p++;
                    n++;
                    break; /* look for another value */
                } else {
                    /* handle escaped VAL_TERM */
                    *d = *p;
                    /* skip past escaped char */
                    p++;
                    i--;
                }
            }
            p++;
            d++;
        }

    }
    if (in_val) {
        return WA_ERR_CORRUPT;
    } else if (i && n == max_num_attrs) {
        return WA_ERR_NO_ROOM;
    } else {
        return n;
    }
}
