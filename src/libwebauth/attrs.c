#include "webauthp.h"
#include <sys/types.h>
#include <netinet/in.h>

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
        al->attrs = malloc(sizeof(WEBAUTH_ATTR)*initial_capacity);
        if (al->attrs==NULL) {
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
        int new_capacity = list->capacity *2;
        int new_size = sizeof(WEBAUTH_ATTR) * new_capacity;
        WEBAUTH_ATTR *new_attrs = 
            (WEBAUTH_ATTR*) realloc(list->attrs, new_size);
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
    int i;
    assert(list != NULL);
    assert(list->attrs != NULL);
    assert(length ? (value != NULL) : 1);
    i = next_entry(list);
    if (i == -1)
        return WA_ERR_NO_MEM;

    if (FLAG_ISSET(flags,WA_COPY_NAME)) {
        list->attrs[i].name = strdup(name);
        if (list->attrs[i].name == NULL)
            return WA_ERR_NO_MEM;            
    } else {
        list->attrs[i].name = name;

    }

    if (FLAG_ISSET(flags, WA_COPY_VALUE)) {
        /* see if it fits in val_buff first */
        if (length < sizeof(list->attrs[i].val_buff)) {
            FLAG_CLEAR(flags, WA_COPY_VALUE);
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
    return webauth_attr_list_add(list, name, (void*)value, 
                                 vlen ? vlen : strlen(value), flags);
}

int
webauth_attr_list_add_uint32(WEBAUTH_ATTR_LIST *list,
                             const char *name,
                             uint32_t value,
                             int flags)
{
    value = htonl(value);
    return webauth_attr_list_add(list, name, (void*)&value, 
                                 sizeof(value),
                                 flags | WA_COPY_VALUE);
}

int
webauth_attr_list_add_int32(WEBAUTH_ATTR_LIST *list,
                            const char *name,
                            int32_t value,
                            int flags)
{

    return webauth_attr_list_add_uint32(list, name, value, flags);
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
        
        if (FLAG_ISSET(list->attrs[i].flags, WA_COPY_NAME))
            free((char*)list->attrs[i].name);

        if (FLAG_ISSET(list->attrs[i].flags, WA_COPY_VALUE))
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
webauth_attr_list_get_void(WEBAUTH_ATTR_LIST *list,
                           const char *name,
                           void **value,
                           int *value_len,
                           int copy)
{
    int i, s;

    assert(list != NULL);
    assert(name != NULL);
    assert(value!= NULL);
    assert(value_len != NULL);

    s = webauth_attr_list_find(list, name, &i);
    if (s != WA_ERR_NONE)
        return s;

    *value_len = list->attrs[i].length;
    if (copy) {
        *value = malloc(*value_len);
        if (*value == NULL)
            return WA_ERR_NO_MEM;
        memcpy(*value, list->attrs[i].value, *value_len);
    } else {
        *value = list->attrs[i].value;
    }
    return WA_ERR_NONE;
}


int
webauth_attr_list_get_str(WEBAUTH_ATTR_LIST *list,
                           const char *name,
                           char **value,
                           int *value_len,
                           int copy)
{
    int i, s, len;

    assert(list != NULL);
    assert(name != NULL);
    assert(value!= NULL);

    s = webauth_attr_list_find(list, name, &i);
    if (s != WA_ERR_NONE)
        return s;

    len = list->attrs[i].length;

    if (value_len)
        *value_len = len;
    if (copy) {
        *value = malloc(len+1);
        if (*value == NULL)
            return WA_ERR_NO_MEM;
        memcpy(*value, list->attrs[i].value, len+1); /*include null */
    } else {
        *value = list->attrs[i].value;
    }
    return WA_ERR_NONE;
}

int
webauth_attr_list_get_uint32(WEBAUTH_ATTR_LIST *list,
                             const char *name,
                             uint32_t *value)
{
    int i, s;

    assert(list != NULL);
    assert(name != NULL);
    assert(value!= NULL);

    s = webauth_attr_list_find(list, name, &i);
    if (s != WA_ERR_NONE)
        return s;
    if (list->attrs[i].length != sizeof(uint32_t)) 
        return WA_ERR_CORRUPT;
    memcpy(value, list->attrs[i].value, sizeof(uint32_t));
    *value = ntohl(*value);
    return WA_ERR_NONE;
}


int
webauth_attr_list_get_int32(WEBAUTH_ATTR_LIST *list,
                            const char *name,
                            int32_t *value)
{
    int i, s;
    uint32_t temp;

    assert(list != NULL);
    assert(name != NULL);
    assert(value != NULL);

    s = webauth_attr_list_find(list, name, &i);
    if (s != WA_ERR_NONE)
        return s;
    if (list->attrs[i].length != sizeof(uint32_t))
        return WA_ERR_CORRUPT;
    memcpy(&temp, list->attrs[i].value, sizeof(uint32_t));
    *value = (int32_t)ntohl(temp);
    return WA_ERR_NONE;
}

int
webauth_attr_list_get_time(WEBAUTH_ATTR_LIST *list, 
                           const char *name,
                           time_t *value)
{
    int i, s;
    uint32_t temp;
    assert(list != NULL);
    assert(name != NULL);
    assert(value != NULL);

    s = webauth_attr_list_find(list, name, &i);
    if (s != WA_ERR_NONE)
        return s;
    if (list->attrs[i].length != sizeof(uint32_t))
        return WA_ERR_CORRUPT;
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
                    length = d - (unsigned char*)value;
                    *d = '\0';
                    s = webauth_attr_list_add(*list, name, value, length, 0);
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
