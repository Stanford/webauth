#include "webauthp.h"

#include <sys/types.h>
#include <netinet/in.h>

/*
 * given an array of attributes, returns the amount
 * of space required to encode them.
 */

#define NAME_TERM '='
#define VAL_TERM ';'

WEBAUTH_ATTR_LIST *
webauth_attr_list_new(int initial_capacity)
{
    WEBAUTH_ATTR_LIST *al;

    al = malloc(sizeof(WEBAUTH_ATTR_LIST));
    if (al != NULL) {
        al->num_attrs = 0;
        al->capacity = initial_capacity;
        al->attrs = malloc(sizeof(WEBAUTH_ATTR)*initial_capacity);
        if (al->attrs==NULL) {
            free(al);
            return NULL;
        }
    }
    return al;
}

int
webauth_attr_list_add(WEBAUTH_ATTR_LIST *list,
                      const char *name, const void *value, int length)
{
    void *v;
    char *n;
    assert(list != NULL);
    assert(list->attrs != NULL);
    assert(length ? (value != NULL) : 1);
    if (list->num_attrs == list->capacity) {
        int new_capacity = list->capacity *2;
        int new_size = sizeof(WEBAUTH_ATTR) * new_capacity;
        WEBAUTH_ATTR *new_attrs = 
            (WEBAUTH_ATTR*) realloc(list->attrs, new_size);
        if (new_attrs == NULL) {
            return WA_ERR_NO_MEM;
        }
        list->capacity = new_capacity;
        if (list->attrs != new_attrs) {
            list->attrs = new_attrs;
        }
    }
    n = strdup(name);
    if (n == NULL) {
        return WA_ERR_NO_MEM;
    }

    v = malloc(length+1);
    if (v == NULL) {
        free(n);
        return WA_ERR_NO_MEM;
    }

    memcpy(v, value, length);
    /* null terminate */
    ((char*)v)[length] = '\0';
    list->attrs[list->num_attrs].name = n;
    list->attrs[list->num_attrs].value = v;
    list->attrs[list->num_attrs].length = length;
    list->num_attrs++;
    return WA_ERR_NONE;
}

int
webauth_attr_list_add_str(WEBAUTH_ATTR_LIST *list,
                          const char *name,
                          const char *value,
                          int vlen)
{
    assert(list != NULL);
    assert(name != NULL);
    assert(value != NULL);
    return webauth_attr_list_add(list, name, value, strlen(value));
}

int
webauth_attr_list_add_uint32(WEBAUTH_ATTR_LIST *list,
                                 const char *name,
                                 uint32_t value)
{
    assert(list != NULL);
    assert(name != NULL);
    value = htonl(value);
    return webauth_attr_list_add(list, name, &value, sizeof(value));
}

int
webauth_attr_list_add_int32(WEBAUTH_ATTR_LIST *list,
                            const char *name,
                            int32_t value)
{
    assert(list != NULL);
    assert(name != NULL);
    value = htonl((uint32_t)value);
    return webauth_attr_list_add(list, name, &value, sizeof(value));
}

int
webauth_attr_list_add_time(WEBAUTH_ATTR_LIST *list, 
                               const char *name,
                               time_t value)
{
    assert(list != NULL);
    assert(name != NULL);
    value = htonl((uint32_t)value);
    return webauth_attr_list_add(list, name, &value, sizeof(value));
}

void
webauth_attr_list_free(WEBAUTH_ATTR_LIST *list)
{
    int i;
    assert(list != NULL);
    assert(list->attrs != NULL);
    for (i=0; i < list->num_attrs; i++) {
        free(list->attrs[i].name);
        free(list->attrs[i].value);
    }
    free(list->attrs);
    free(list);
}

int
webauth_attr_list_find(WEBAUTH_ATTR_LIST *list, const char *name)
{
    int i;

    assert(list != NULL);
    assert(name != NULL);

    for (i=0; i < list->num_attrs; i++) {
        if (strcmp(list->attrs[i].name, name) == 0) {
            return i;
        }
    }

    return WA_ERR_NOT_FOUND;
}

int
webauth_attr_list_get_uint32(WEBAUTH_ATTR_LIST *list,
                             const char *name,
                             uint32_t *value)
{
    int i;

    assert(list != NULL);
    assert(name != NULL);
    assert(value!= NULL);

    i = webauth_attr_list_find(list, name);
    if (i == WA_ERR_NOT_FOUND) {
        return i;
    }
    if (list->attrs[i].length != sizeof(uint32_t)) {
        return WA_ERR_CORRUPT;
    }
    memcpy(value, list->attrs[i].value, sizeof(uint32_t));
    *value = ntohl(*value);
    return WA_ERR_NONE;
}


int
webauth_attr_list_get_int32(WEBAUTH_ATTR_LIST *list,
                            const char *name,
                            int32_t *value)
{
    int i;
    uint32_t temp;

    assert(list != NULL);
    assert(name != NULL);
    assert(value != NULL);

    i = webauth_attr_list_find(list, name);
    if (i == WA_ERR_NOT_FOUND) {
        return i;
    }
    if (list->attrs[i].length != sizeof(uint32_t)) {
        return WA_ERR_CORRUPT;
    }
    memcpy(&temp, list->attrs[i].value, sizeof(uint32_t));
    *value = (int32_t)ntohl(temp);
    return WA_ERR_NONE;
}

int
webauth_attr_list_get_time(WEBAUTH_ATTR_LIST *list, 
                           const char *name,
                           time_t *value)
{
    int i;
    uint32_t temp;
    assert(list != NULL);
    assert(name != NULL);
    assert(value != NULL);

    i = webauth_attr_list_find(list, name);
    if (i == WA_ERR_NOT_FOUND) {
        return i;
    }
    if (list->attrs[i].length != sizeof(uint32_t)) {
        return WA_ERR_CORRUPT;
    }
    memcpy(&temp, list->attrs[i].value, sizeof(uint32_t));
    *value = (time_t)ntohl(temp);
    return WA_ERR_NONE;
}

int
webauth_attrs_encoded_length(const WEBAUTH_ATTR_LIST *list)
{
    int space, i, len;
    unsigned char *p, *v;
    
    assert(list);

    space = 0;
    for (i=0; i < list->num_attrs; i++) {
        space += strlen(list->attrs[i].name) + 1;  /* +1 for NAME_TERM */
        v = list->attrs[i].value;
        len = list->attrs[i].length;
        while (len && (p = memchr(v, VAL_TERM, len))) {
            space++; /* add one for each VAL_TERM; we find */
            len -= p+1-v;
            v = p+1;
        } 
        space += list->attrs[i].length + 1; /* +1 for VAL_TERM */
    }
    return space;
}

/*
 * given an array of attributes, encode them into output.
 */

int
webauth_attrs_encode(const WEBAUTH_ATTR_LIST *list,
                     unsigned char *output,
                     int *output_len,
                     int max_output_len)
{
   int i, len, slen, rlen;
   unsigned char *p, *v, *d;

    assert(list != NULL);
    assert(list->attrs);
    assert(list->num_attrs > 0);
    assert(output != NULL);

    *output_len = 0;

    rlen = webauth_attrs_encoded_length(list);

    if (rlen > max_output_len) {
        return WA_ERR_NO_ROOM;
    }

    d = output;

    for (i=0; i < list->num_attrs; i++) {
        len = strlen(list->attrs[i].name);
        memcpy(d, list->attrs[i].name, len);
        d += len;
        *d++ = NAME_TERM;
        v = list->attrs[i].value;
        len = list->attrs[i].length;
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
    *output_len = d - output;
    return WA_ERR_NONE;
}

/*
 * decodes the given buffer into an array of attributes.
 * The buffer is modifed.
 */

int
webauth_attrs_decode(unsigned char *buffer, 
                     int input_len,
                     WEBAUTH_ATTR_LIST **list)
{
    int i, in_val, length, s;
    unsigned char *p, *d, *name;
    void *value;

    assert(buffer != NULL);
    assert(input_len > 0);
    assert(list != NULL);

    *list = webauth_attr_list_new(64);
    if (*list == NULL) {
        return WA_ERR_NO_MEM;
    }

    i = input_len;
    p = buffer;
    in_val = 0;

    while (i >0) {
        name = p;
        p++; 
        i--;
        while (i && *p != NAME_TERM) {
            p++;
            i--;
        }
        if (i==0 || *p != NAME_TERM) {
            webauth_attr_list_free(*list);
            *list = NULL;
            return WA_ERR_CORRUPT; /* no NAME_TERM found */
        }
        *p = '\0'; /* null terminate name */
        p++;
        i--;
        if (!i) {
            webauth_attr_list_free(*list);
            *list = NULL;
            return WA_ERR_CORRUPT; /* missing val term */
        }

        value = p;
        d = p;
        in_val = 1;

        while(i-- > 0) {
            if (*p != VAL_TERM) {
                if (d != p) {
                    *d = *p;
                }
            } else {
                if (!i || *(p+1) != VAL_TERM) {
                    /* end of value */
                    in_val = 0;
                    length = d - (unsigned char*)value;
                    *d = '\0';
                    s = webauth_attr_list_add(*list, name, value, length);
                    if (s!=WA_ERR_NONE) {
                        webauth_attr_list_free(*list);
                        *list = NULL;
                        return s;
                    }
                    d++;
                    p++;
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
        webauth_attr_list_free(*list);
        *list = NULL;
        return WA_ERR_CORRUPT;
    } else {
        return WA_ERR_NONE;
    }
}

/*
**  Local variables:
**  mode: c
**  c-basic-offset: 4
**  indent-tabs-mode: nil
**  end:
*/
