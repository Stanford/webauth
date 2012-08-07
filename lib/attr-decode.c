/*
 * Low-level attribute decoding.
 *
 * Provided here is a table-driven decoder that fills out the elements of a
 * struct from a WebAuth attribute encoding.  This is the encoding used inside
 * tokens and for some other WebAuth persistant data structures, such as
 * service token caches and keyrings.
 *
 * Currently, this still uses the WebAuth attribute list code beneath, but
 * eventually will do attribute encoding directly.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <lib/internal.h>
#include <util/macros.h>
#include <webauth.h>
#include <webauth/basic.h>

/*
 * Macros used to resolve a void * pointer to a struct and an offset into a
 * pointer to the appropriate type.  Scary violations of the C type system
 * lurk here.
 */
#define LOC_DATA(d, o)   (void **)    (void *)((char *) (d) + (o))
#define LOC_INT32(d, o)  (int32_t *)  (void *)((char *) (d) + (o))
#define LOC_STRING(d, o) (char **)    (void *)((char *) (d) + (o))
#define LOC_SIZE(d, o)   (size_t *)   (void *)((char *) (d) + (o))
#define LOC_TIME(d, o)   (time_t *)   (void *)((char *) (d) + (o))
#define LOC_UINT32(d, o) (uint32_t *) (void *)((char *) (d) + (o))


/*
 * Report an error while encoding an attribute.  Takes the WebAuth context,
 * status, description, context (for repeated elements), and element number
 * (for repeated elements).  This is an internal helper function for
 * decode_from_attrs.
 */
static void
decode_error_set(struct webauth_context *ctx, int status, const char *desc,
                 const char *context, size_t element)
{
    if (context != NULL && element != 0)
        webauth_error_set(ctx, status, "decoding %s %s %lu", context, desc,
                          (unsigned long) element);
    else
        webauth_error_set(ctx, status, "decoding %s", desc);
}


/*
 * Given an encoding specification, an attribute list, and a data structure,
 * decode attributes into that data structure.  Takes a separate pool to use
 * rather than using the normal WebAuth context pool.  Context is a string to
 * prepend to the description for error reporting.  If element is non-zero, we
 * are handling a repeated attribute encoding, and the element number is
 * appended to the attribute name when decoding it.
 *
 * This is an internal helper function used by webauth_decode.
 */
static int
decode_from_attrs(struct webauth_context *ctx, apr_pool_t *pool,
                  const struct webauth_encoding *rules,
                  WEBAUTH_ATTR_LIST *alist, const void *result,
                  const char *context, unsigned long element)
{
    const struct webauth_encoding *rule;
    const char *attr;
    unsigned long i;
    ssize_t index;
    int status;
    void *data;
    void **repeat;
    int32_t int32;
    char *string;
    char **out;
    size_t size;
    time_t time;
    uint32_t uint32;

    for (rule = rules; rule->attr != NULL; rule++) {
        if (element == 0)
            attr = rule->attr;
        else
            attr = apr_psprintf(pool, "%s%lu", rule->attr, element);
        if (rule->optional)
            if (webauth_attr_list_find(alist, attr, &index) != WA_ERR_NONE)
                continue;
        switch (rule->type) {
        case WA_TYPE_DATA:
            status = webauth_attr_list_get(alist, attr, &data, &size,
                                           WA_F_NONE);
            if (status != WA_ERR_NONE)
                break;
            *LOC_DATA(result, rule->offset) = apr_pmemdup(pool, data, size);
            *LOC_SIZE(result, rule->len_offset) = size;
            break;
        case WA_TYPE_STRING:
            status = webauth_attr_list_get_str(alist, attr, &string, &size,
                                               WA_F_NONE);
            if (status != WA_ERR_NONE)
                break;
            out = LOC_STRING(result, rule->offset);
            *out = apr_palloc(pool, size + 1);
            memcpy(*out, string, size);
            (*out)[size] = '\0';
            break;
        case WA_TYPE_INT32:
            status = webauth_attr_list_get_int32(alist, attr, &int32,
                                                 WA_F_NONE);
            if (status != WA_ERR_NONE)
                break;
            *LOC_INT32(result, rule->offset) = int32;
            break;
        case WA_TYPE_UINT32:
            status = webauth_attr_list_get_uint32(alist, attr, &uint32,
                                                  WA_F_NONE);
            if (status != WA_ERR_NONE)
                break;
            *LOC_UINT32(result, rule->offset) = uint32;
            break;
        case WA_TYPE_TIME:
            status = webauth_attr_list_get_time(alist, attr, &time, WA_F_NONE);
            if (status != WA_ERR_NONE)
                break;
            *LOC_TIME(result, rule->offset) = time;
            break;
        case WA_TYPE_REPEAT:
            status = webauth_attr_list_get_uint32(alist, attr, &uint32,
                                                  WA_F_NONE);
            if (status != WA_ERR_NONE)
                break;
            *LOC_UINT32(result, rule->len_offset) = uint32;
            repeat = LOC_DATA(result, rule->offset);
            *repeat = apr_palloc(pool, rule->size * uint32);
            for (i = 0; i < uint32; i++) {
                data = (char *) *repeat + i * rule->size;
                status = decode_from_attrs(ctx, pool, rules->repeat, alist,
                                           data, attr, i);
                if (status != WA_ERR_NONE)
                    return status;
            }
            break;
        }
        if (status != WA_ERR_NONE) {
            decode_error_set(ctx, status, rule->desc, context, element);
            return status;
        }
    }
    return WA_ERR_NONE;
}


/*
 * Given an encoding specification, an attribute list, and a data structure,
 * decode that attribute list into the data structure as newly-allocated pool
 * memory.  Takes a separate pool to use rather than using the normal WebAuth
 * context pool.
 *
 * FIXME: This currently still uses the underlying attribute code, but should
 * be split off into its own implementation and made independent of that.
 */
int
webauth_decode(struct webauth_context *ctx, apr_pool_t *pool,
               const struct webauth_encoding *rules, const void *input,
               size_t length, void *data)
{
    WEBAUTH_ATTR_LIST *alist;
    int status;
    void *buf;

    buf = apr_pmemdup(pool, input, length);
    status = webauth_attrs_decode(buf, length, &alist);
    if (status != WA_ERR_NONE) {
        webauth_error_set(ctx, status, "decoding attributes");
        return status;
    }
    status = decode_from_attrs(ctx, pool, rules, alist, data, NULL, 0);
    webauth_attr_list_free(alist);
    return status;
}
