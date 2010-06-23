/*
 * Functions to manipulate attribute lists.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2006, 2009, 2010
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing term.s
 */

#include <config.h>

#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#include <stdio.h>
#include <sys/types.h>

#include <lib/webauthp.h>

#define NAME_TERM '='
#define VAL_TERM  ';'

#define FLAG_ISSET(flags, flag) (((flags) & (flag)) == (flag))
#define FLAG_CLEAR(flags, flag) ((flags) &= ~(flag))


/*
 * Allocate a new list of attributes sufficient in size to hold
 * initial_capacity elements.  Returns the newly allocated list or NULL on
 * failure.
 */
WEBAUTH_ATTR_LIST *
webauth_attr_list_new(size_t initial_capacity)
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
 * Return the next available free entry in an attribute list or -1 if it is
 * out of free entries.
 */
static
ssize_t next_entry(WEBAUTH_ATTR_LIST *list)
{
    size_t i = list->num_attrs;

    assert(list != NULL);
    assert(list->attrs != NULL);

    if (list->num_attrs == list->capacity) {
        size_t new_capacity = list->capacity * 2;
        size_t new_size = sizeof(WEBAUTH_ATTR) * new_capacity;
        WEBAUTH_ATTR *new_attrs = realloc(list->attrs, new_size);

        if (new_attrs == NULL)
            return -1;
        list->capacity = new_capacity;
        if (list->attrs != new_attrs)
            list->attrs = new_attrs;
    }
    list->num_attrs++;
    return i;
}


/*
 * Add an attribute to a list.  Takes the attribute list, the name of the
 * attribute, its value and length, and any flags.  Returns a WA_ERR code.
 */
int
webauth_attr_list_add(WEBAUTH_ATTR_LIST *list, const char *name, void *value,
                      size_t length, unsigned int flags)
{
    ssize_t i;
    int s;
    char *buff = NULL;

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
    } else
        list->attrs[i].name = name;

    if (FLAG_ISSET(flags, WA_F_FMT_B64)) {
        size_t elen, blen = webauth_base64_encoded_length(length);

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
        size_t elen;
        size_t hlen = webauth_hex_encoded_length(length);

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

    /*
     * If we're copying the value and we haven't already encoded it, first
     * check if it fits in val_buff.  If so, use that; if not, allocate new
     * memory for the value.
     */
    if (FLAG_ISSET(flags, WA_F_COPY_VALUE) && buff == NULL) {
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
    } else
        list->attrs[i].value = value;
    list->attrs[i].length = length;
    list->attrs[i].flags = flags;
    return WA_ERR_NONE;
}


/*
 * Add a string attribute to an attribute list.  Takes the value and the
 * length of the value.  If the length of the value is 0, compute the length
 * with strlen.  Returns a WA_ERR code.
 */
int
webauth_attr_list_add_str(WEBAUTH_ATTR_LIST *list, const char *name,
                          const char *value, size_t vlen, unsigned int flags)
{
    assert(value != NULL);
    return webauth_attr_list_add(list, name, (void *) value,
                                 vlen ? vlen : strlen(value), flags);
}


/*
 * Add a 32-bit unsigned integer attribute to an attribute list.  Returns a
 * WA_ERR code.
 */
int
webauth_attr_list_add_uint32(WEBAUTH_ATTR_LIST *list, const char *name,
                             uint32_t value, unsigned int flags)
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


/*
 * Add a 32-bit signed integer attribute to an attribute list.  Returns a
 * WA_ERR code.
 */
int
webauth_attr_list_add_int32(WEBAUTH_ATTR_LIST *list, const char *name,
                            int32_t value, unsigned int flags)
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


/*
 * Add a timestamp in seconds since UNIX epoch to an attribute list.  This can
 * currently only represent 32-bit time values.  Returns a WA_ERR code.
 */
int
webauth_attr_list_add_time(WEBAUTH_ATTR_LIST *list, const char *name,
                           time_t value, unsigned int flags)
{
    return webauth_attr_list_add_uint32(list, name, value, flags);
}


/*
 * Free an attribute list.
 */
void
webauth_attr_list_free(WEBAUTH_ATTR_LIST *list)
{
    size_t i;

    assert(list != NULL);
    assert(list->attrs != NULL);

    for (i = 0; i < list->num_attrs; i++) {
        if (FLAG_ISSET(list->attrs[i].flags, WA_F_COPY_NAME))
            free((char *) list->attrs[i].name);
        if (FLAG_ISSET(list->attrs[i].flags, WA_F_COPY_VALUE))
            free(list->attrs[i].value);
    }
    free(list->attrs);
    free(list);
}


/*
 * Find a particular attribute in an attribute list and store its index in
 * the index parameter.  Returns a WA_ERR code.
 */
int
webauth_attr_list_find(WEBAUTH_ATTR_LIST *list, const char *name,
                       ssize_t *index)
{
    size_t i;

    assert(list != NULL);
    assert(name != NULL);
    assert(index != NULL);

    for (i = 0; i < list->num_attrs; i++)
        if (strcmp(list->attrs[i].name, name) == 0) {
            *index = i;
            return WA_ERR_NONE;
        }
    *index = -1;
    return WA_ERR_NOT_FOUND;
}


/*
 * Retrieve a specific attribute by name.  Stores its value in the value
 * parameter and its length in the value_len parameter.  Returns a WA_ERR
 * code.
 */
int
webauth_attr_list_get(WEBAUTH_ATTR_LIST *list, const char *name, void **value,
                      size_t *value_len, unsigned int flags)
{
    ssize_t i;
    int s;

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
        if (s != WA_ERR_NONE)
            return s;
    } else
        *value_len = list->attrs[i].length;

    /* Allocate an extra byte for the trailing nul. */
    if (FLAG_ISSET(flags, WA_F_COPY_VALUE)) {
        *value = malloc(*value_len + 1);
        if (*value == NULL)
            return WA_ERR_NO_MEM;
    } else
        *value = list->attrs[i].value;

    /*
     * See if we have to decode or copy.  If copying, copy an extra byte to
     * get the trailing nul.
     */
    if (FLAG_ISSET(flags, WA_F_FMT_B64)) {
        s = webauth_base64_decode(list->attrs[i].value, list->attrs[i].length,
                                  *value, value_len, *value_len);
        if (s != WA_ERR_NONE) {
            if (FLAG_ISSET(flags, WA_F_COPY_VALUE))
                free(*value);
            return s;
        }
        *((char *)(*value) + *value_len) = '\0';
    } else if (FLAG_ISSET(flags, WA_F_FMT_HEX)) {
        s = webauth_hex_decode(list->attrs[i].value, list->attrs[i].length,
                               *value, value_len, *value_len);
        if (s != WA_ERR_NONE) {
            if (FLAG_ISSET(flags, WA_F_COPY_VALUE))
                free(*value);
            return s;
        }
        *((char *)(*value) + *value_len) = '\0';
    } else if (FLAG_ISSET(flags, WA_F_COPY_VALUE))
        memcpy(*value, list->attrs[i].value, *value_len + 1);
    return WA_ERR_NONE;
}


/*
 * Retrieve a string attribute by name.  Stores the string in value and the
 * length of the string in value_len.  Returns a WA_ERR code.
 */
int
webauth_attr_list_get_str(WEBAUTH_ATTR_LIST *list, const char *name,
                          char **value, size_t *value_len, unsigned int flags)
{
    return webauth_attr_list_get(list, name, (void **) value, value_len,
                                 flags);
}


/*
 * Retrieve an unsigned 32-bit integer attribute by name.  Stores the value in
 * value.  Returns a WA_ERR code.
 */
int
webauth_attr_list_get_uint32(WEBAUTH_ATTR_LIST *list, const char *name,
                             uint32_t *value, unsigned int flags)
{
    int s;
    size_t vlen;
    void *v;

    v = NULL;
    s = webauth_attr_list_get(list, name, &v, &vlen, flags);

    if (s == WA_ERR_NONE) {
        if (FLAG_ISSET(flags, WA_F_FMT_STR))
            *value = atol((char *) v);
        else {
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


/*
 * Retrieve a signed 32-bit integer attribute by name.  Stores the value in
 * value.  Returns a WA_ERR code.
 */
int
webauth_attr_list_get_int32(WEBAUTH_ATTR_LIST *list, const char *name,
                            int32_t *value, unsigned int flags)
{
    return webauth_attr_list_get_uint32(list, name, (uint32_t *) value,
                                        flags);
}


/*
 * Retrieve a timestamp attribute by name, assuming that a timestamp will fit
 * into a 32-bit integer.  Stores the value in value.  Returns a WA_ERR code.
 */
int
webauth_attr_list_get_time(WEBAUTH_ATTR_LIST *list, const char *name,
                           time_t *value, unsigned int flags)
{
    uint32_t value32;
    int status;

    status = webauth_attr_list_get_uint32(list, name, &value32, flags);
    if (status == WA_ERR_NONE)
        *value = value32;
    return status;
}


/*
 * Given an attribute list, returns the size of buffer required for an
 * encoding of that attribute list.
 */
size_t
webauth_attrs_encoded_length(const WEBAUTH_ATTR_LIST *list)
{
    size_t space, i, len;
    char *p, *v;

    assert(list);

    /*
     * Add an extra character for each attribute name for the sign after the
     * attribute name and an extra character for each value for the separator
     * between attributes.
     */
    space = 0;
    for (i = 0; i < list->num_attrs; i++) {
        space += strlen(list->attrs[i].name) + 1;
        v = list->attrs[i].value;
        len = list->attrs[i].length;

        /*
         * Add an extra character for each occurrence of the separator between
         * attributes that we'll have to escape.
         */
        while (len && (p = memchr(v, VAL_TERM, len))) {
            space++; /* add one for each VAL_TERM; we find */
            len -= p + 1 - v;
            v = p + 1;
        }
        space += list->attrs[i].length + 1;
    }
    return space;
}


/*
 * Given an array of attributes, encode them into output, storing the encoded
 * length in output_len.  max_output_len gives the size of the output buffer.
 * Returns a WA_ERR code.
 */
int
webauth_attrs_encode(const WEBAUTH_ATTR_LIST *list, char *output,
                     size_t *output_len, size_t max_output_len)
{
    size_t i, len, slen, rlen;
    char *p, *v, *d;

    assert(list != NULL);
    assert(list->attrs);
    assert(list->num_attrs > 0);
    assert(output != NULL);

    *output_len = 0;

    rlen = webauth_attrs_encoded_length(list);
    if (rlen > max_output_len)
        return WA_ERR_NO_ROOM;

    d = output;

    for (i = 0; i < list->num_attrs; i++) {
        len = strlen(list->attrs[i].name);
        memcpy(d, list->attrs[i].name, len);
        d += len;
        *d++ = NAME_TERM;
        v = list->attrs[i].value;
        len = list->attrs[i].length;

        /* Escape any VAL_TERM in the value by doubling it. */
        while (len != 0 && (p = memchr(v, VAL_TERM, len))) {
            slen = p - v + 1;
            memcpy(d, v, slen);
            d += slen;
            *d++ = VAL_TERM;
            len -= slen;
            v = p + 1;
        }

        /* Copy the rest of the value. */
        if (len != 0) {
            memcpy(d, v, len);
            d += len;
        }

        /* Append VAL_TERM to the end of the value. */
        *d++ = VAL_TERM;
    }
    *output_len = d - output;
    return WA_ERR_NONE;
}


/*
 * Decodes the given buffer into an array of attributes, newly allocated,
 * which is stored in list.  The buffer is modifed as part of the decoding
 * process.  Returns a WA_ERR code.
 */
int
webauth_attrs_decode(char *buffer, size_t input_len, WEBAUTH_ATTR_LIST **list)
{
    size_t i, in_val, length;
    int s;
    char *p, *d, *name;
    void *value;

    assert(buffer != NULL);
    assert(input_len > 0);
    assert(list != NULL);

    *list = webauth_attr_list_new(16);
    if (*list == NULL)
        return WA_ERR_NO_MEM;

    i = input_len;
    p = buffer;
    in_val = 0;

    while (i > 0) {
        name = p;
        p++;
        i--;
        while (i > 0 && *p != NAME_TERM) {
            p++;
            i--;
        }

        /* If we can't find NAME_TERM, give up as corrupt. */
        if (i == 0 || *p != NAME_TERM) {
            webauth_attr_list_free(*list);
            *list = NULL;
            return WA_ERR_CORRUPT;
        }

        /* Null-terminate the name. */
        *p = '\0';
        p++;
        i--;

        /*
         * If that's the end of the string, there's no value and the attribute
         * list is corrupt.
         */
        if (i == 0) {
            webauth_attr_list_free(*list);
            *list = NULL;
            return WA_ERR_CORRUPT;
        }

        value = p;
        d = p;
        in_val = 1;

        /*
         * Loop while there are characters remaining in the input buffer.  For
         * any character that isn't a separator between attributes, copy it
         * into the output.  Otherwise, if this is the end of the string or if
         * there is a single separator, that's the end of the attribute; add
         * it to the list and break out for the next attribute.  If there are
         * two separators in a row, that's an escaped separator; copy the
         * separator to the output and continue.
         */
        while (i > 0) {
            i--;
            if (*p != VAL_TERM) {
                if (d != p)
                    *d = *p;
            } else {
                if (i == 0 || *(p + 1) != VAL_TERM) {
                    in_val = 0;
                    length = d - (char *) value;
                    *d = '\0';
                    s = webauth_attr_list_add(*list, name, value, length,
                                              WA_F_NONE);
                    if (s != WA_ERR_NONE) {
                        webauth_attr_list_free(*list);
                        *list = NULL;
                        return s;
                    }
                    d++;
                    p++;
                    break;
                } else {
                    *d = *p;
                    p++;
                    i--;
                }
            }
            p++;
            d++;
        }
    }

    /*
     * If we're still in a value at the end of the encoded attribute list, it
     * was corrupt; abort with an error.  This means the final value also has
     * to be terminated by a semicolon.
     */
    if (in_val != 0) {
        webauth_attr_list_free(*list);
        *list = NULL;
        return WA_ERR_CORRUPT;
    }
    return WA_ERR_NONE;
}
