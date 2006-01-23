#include "webauthp.h"
#include <sys/types.h>
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#include <stdio.h>
/*
 * given an array of attributes, returns the amount
 * of space required to encode them.
 */

#define NAME_TERM '='
#define VAL_TERM ';'


#define FLAG_ISSET(flags, flag) ((flags & flag) == flag)
#define FLAG_CLEAR(flags, flag) (flags &= ~flag)

WEBAUTH_ATTR_LIST *
webauth_attr_list_new(int initial_capacity)
{
    WEBAUTH_ATTR_LIST *al;

    al = malloc(sizeof(WEBAUTH_ATTR_LIST));
    if (al != NULL) {
        al->num_attrs = 0;
        al->capacity = initial_capacity;
        al->attrs = malloc(sizeof(WEBAUTH_ATTR) * initial_capacity);
        if (al->attrs == NULL) {
            free(al);
            return NULL;
        }
    }
    return al;
}

/*
 * return next available entry or -1 if out of mem
 */
static
int next_entry(WEBAUTH_ATTR_LIST *list)
{
    int i = list->num_attrs;

    assert(list != NULL);
    assert(list->attrs != NULL);
    if (list->num_attrs == list->capacity) {
        int new_capacity = list->capacity * 2;
        int new_size = sizeof(WEBAUTH_ATTR) * new_capacity;
        WEBAUTH_ATTR *new_attrs = realloc(list->attrs, new_size);

        if (new_attrs == NULL) {
            return -1;
        }
        list->capacity = new_capacity;
        if (list->attrs != new_attrs) {
            list->attrs = new_attrs;
        }
    }
    list->num_attrs++;
    return i;
}

int
webauth_attr_list_add(WEBAUTH_ATTR_LIST *list,
                      const char *name, 
                      void *value, int length,
                      int flags)
{
    int i, s;
    char *buff;

    buff = NULL;

    assert(list != NULL);
    assert(list->attrs != NULL);
    assert(length ? (value != NULL) : 1);
    i = next_entry(list);
    if (i == -1)
        return WA_ERR_NO_MEM;

    if (FLAG_ISSET(flags, WA_F_COPY_NAME)) {
        list->attrs[i].name = strdup(name);
        if (list->attrs[i].name == NULL)
            return WA_ERR_NO_MEM;            
    } else {
        list->attrs[i].name = name;
    }

    if (FLAG_ISSET(flags, WA_F_FMT_B64)) {
        int elen, blen = webauth_base64_encoded_length(length);

        buff = malloc(blen);
        if (buff == NULL)
            return WA_ERR_NO_MEM;
        s = webauth_base64_encode(value, length, buff, &elen, blen);
        if (s != WA_ERR_NONE) {
            free(buff);
            return s;
        }
        value = buff;
        length = elen;
        flags |= WA_F_COPY_VALUE;
    } else if (FLAG_ISSET(flags, WA_F_FMT_HEX)) {
        int elen, hlen = webauth_hex_encoded_length(length);

        buff = malloc(hlen);
        if (buff == NULL)
            return WA_ERR_NO_MEM;
        s = webauth_hex_encode(value, length, buff, &elen, hlen);
        if (s != WA_ERR_NONE) {
            free(buff);
            return s;
        }
        value = buff;
        length = elen;
        flags |= WA_F_COPY_VALUE;        
    }

    if (FLAG_ISSET(flags, WA_F_COPY_VALUE) && (buff == NULL)) {
        /* see if it fits in val_buff first */
        if (length < sizeof(list->attrs[i].val_buff)) {
            FLAG_CLEAR(flags, WA_F_COPY_VALUE);
            memcpy(list->attrs[i].val_buff, value, length);
            list->attrs[i].value = list->attrs[i].val_buff;
        } else {
            list->attrs[i].value = malloc(length);
            if (list->attrs[i].value == NULL)
                return WA_ERR_NO_MEM;
            memcpy(list->attrs[i].value, value, length);
        }
    } else {
        list->attrs[i].value = value;
    }
    list->attrs[i].length = length;
    list->attrs[i].flags = flags;
    return WA_ERR_NONE;
}

int
webauth_attr_list_add_str(WEBAUTH_ATTR_LIST *list,
                          const char *name,
                          const char *value,
                          int vlen,
                          int flags)
{
    assert(value != NULL);
    return webauth_attr_list_add(list, name, (char *) value,
                                 vlen ? vlen : strlen(value), flags);
}

int
webauth_attr_list_add_uint32(WEBAUTH_ATTR_LIST *list,
                             const char *name,
                             uint32_t value,
                             int flags)
{
    if (FLAG_ISSET(flags, WA_F_FMT_STR)) {
        char buff[32];

        sprintf(buff, "%lu", (unsigned long) value);
        return webauth_attr_list_add_str(list, name, buff, 0,
                                         flags | WA_F_COPY_VALUE);
    } else {
        value = htonl(value);
        return webauth_attr_list_add(list, name, &value, sizeof(value),
                                     flags | WA_F_COPY_VALUE);
    }
}

int
webauth_attr_list_add_int32(WEBAUTH_ATTR_LIST *list,
                            const char *name,
                            int32_t value,
                            int flags)
{
    if (FLAG_ISSET(flags, WA_F_FMT_STR)) {
        char buff[32];

        sprintf(buff, "%ld", (unsigned long) value);
        return webauth_attr_list_add_str(list, name, buff, 0,
                                         flags | WA_F_COPY_VALUE);
    } else {
        value = htonl(value);
        return webauth_attr_list_add(list, name, &value, sizeof(value),
                                     flags | WA_F_COPY_VALUE);
    }
}

int
webauth_attr_list_add_time(WEBAUTH_ATTR_LIST *list, 
                           const char *name,
                           time_t value,
                           int flags)
{
    return webauth_attr_list_add_uint32(list, name, value, flags);
}

void
webauth_attr_list_free(WEBAUTH_ATTR_LIST *list)
{
    int i;
    assert(list != NULL);
    assert(list->attrs != NULL);
    for (i=0; i < list->num_attrs; i++) {
        if (FLAG_ISSET(list->attrs[i].flags, WA_F_COPY_NAME))
            free((char *) list->attrs[i].name);
        if (FLAG_ISSET(list->attrs[i].flags, WA_F_COPY_VALUE))
            free(list->attrs[i].value);
    }
    free(list->attrs);
    free(list);
}

int
webauth_attr_list_find(WEBAUTH_ATTR_LIST *list, const char *name, int *index)
{
    int i;

    assert(list != NULL);
    assert(name != NULL);
    assert(index != NULL);

    for (i=0; i < list->num_attrs; i++) {
        if (strcmp(list->attrs[i].name, name) == 0) {
            *index = i;
            return WA_ERR_NONE;
        }
    }
    *index = -1;
    return WA_ERR_NOT_FOUND;
}

int
webauth_attr_list_get(WEBAUTH_ATTR_LIST *list,
                      const char *name,
                      void **value,
                      int *value_len,
                      int flags)
{
    int i, s;

    assert(list != NULL);
    assert(name != NULL);
    assert(value!= NULL);
    assert(value_len != NULL);

    s = webauth_attr_list_find(list, name, &i);
    if (s != WA_ERR_NONE)
        return s;

    if (FLAG_ISSET(flags, WA_F_FMT_B64)) {
        s = webauth_base64_decoded_length(list->attrs[i].value,
                                          list->attrs[i].length,
                                          value_len);
        if (s!= WA_ERR_NONE)
            return s;
    } else if (FLAG_ISSET(flags, WA_F_FMT_HEX)) {
        s = webauth_hex_decoded_length(list->attrs[i].length, value_len);
        if (s!= WA_ERR_NONE)
            return s;
    } else {
        *value_len = list->attrs[i].length;
    }

    if (FLAG_ISSET(flags, WA_F_COPY_VALUE)) {
        *value = malloc(*value_len + 1);
        if (*value == NULL)
            return WA_ERR_NO_MEM;
    } else {
        *value = list->attrs[i].value;
    }

    /* see if we have to decode, this may be in place if WA_F_COPY_VALUE
     * wasn't set, B64 and HEX always have remove to decode in place.
     */
    if (FLAG_ISSET(flags, WA_F_FMT_B64)) {
        s = webauth_base64_decode(list->attrs[i].value,
                                  list->attrs[i].length,
                                  *value,
                                  value_len,
                                  *value_len);
        if (s!= WA_ERR_NONE) {
            if (FLAG_ISSET(flags, WA_F_COPY_VALUE)) {
                free(*value);
            }
            return s;
        }
        /* always have remove for null-termination */
        *((char *)(*value) + *value_len) = '\0';
    } else if (FLAG_ISSET(flags, WA_F_FMT_HEX)) {
        s = webauth_hex_decode(list->attrs[i].value,
                               list->attrs[i].length,
                               *value,
                               value_len,
                               *value_len);
        if (s!= WA_ERR_NONE) {
            if (FLAG_ISSET(flags, WA_F_COPY_VALUE)) {
                free(*value);
            }
            return s;
        }
        /* always have remove for null-termination */
        *((char *)(*value) + *value_len) = '\0';
    } else if (FLAG_ISSET(flags, WA_F_COPY_VALUE)) {
        /* if we didn't decode and are copying, need to copy current */
        memcpy(*value, list->attrs[i].value, *value_len + 1); /* +1 for NULL */
    }
    return WA_ERR_NONE;
}


int
webauth_attr_list_get_str(WEBAUTH_ATTR_LIST *list,
                           const char *name,
                           char **value,
                           int *value_len,
                           int flags)
{
    return webauth_attr_list_get(list, name, (void **) value, value_len,
                                 flags);
}

int
webauth_attr_list_get_uint32(WEBAUTH_ATTR_LIST *list,
                             const char *name,
                             uint32_t *value,
                             int flags)
{
    int s, vlen;
    void *v;
    v = NULL;
    s = webauth_attr_list_get(list, name, &v, &vlen, flags);

    if (s == WA_ERR_NONE) {
        if (FLAG_ISSET(flags, WA_F_FMT_STR)) {
            *value = atol((char *) v);
        } else {
            if (vlen != sizeof(uint32_t)) {
                s = WA_ERR_CORRUPT;
                goto cleanup;
            }   
            memcpy(value, v, vlen);
            *value = ntohl(*value);
        }
    }

 cleanup:
    if (FLAG_ISSET(flags, WA_F_COPY_VALUE))
        free(v);
    return s;
}


int
webauth_attr_list_get_int32(WEBAUTH_ATTR_LIST *list,
                            const char *name,
                            int32_t *value,
                            int flags)
{
    return webauth_attr_list_get_uint32(list, name, (uint32_t *) value, flags);
}

int
webauth_attr_list_get_time(WEBAUTH_ATTR_LIST *list, 
                           const char *name,
                           time_t *value,
                           int flags)
{
    return webauth_attr_list_get_uint32(list, name, (uint32_t *) value, flags);
}

int
webauth_attrs_encoded_length(const WEBAUTH_ATTR_LIST *list)
{
    int space, i, len;
    char *p, *v;
    
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
                     char *output,
                     int *output_len,
                     int max_output_len)
{
    int i, len, slen, rlen;
    char *p, *v, *d;

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
webauth_attrs_decode(char *buffer, 
                     int input_len,
                     WEBAUTH_ATTR_LIST **list)
{
    int i, in_val, length, s;
    char *p, *d, *name;
    void *value;

    assert(buffer != NULL);
    assert(input_len > 0);
    assert(list != NULL);

    *list = webauth_attr_list_new(16);
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
                    length = d - (char *) value;
                    *d = '\0';
                    s = webauth_attr_list_add(*list, name, value, length,
                                              WA_F_NONE);
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
