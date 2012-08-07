/*
 * Low-level attribute encoding.
 *
 * Provided here is a table-driven encoder that transforms a struct into
 * WebAuth attribute encoding.  This is the encoding used inside tokens and
 * for some other WebAuth persistant data structures, such as service token
 * caches and keyrings.
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
 * encode_to_attrs.
 */
static void
encode_error_set(struct webauth_context *ctx, int status, const char *desc,
                 const char *context, size_t element)
{
    if (context != NULL && element != 0)
        webauth_error_set(ctx, status, "encoding %s %s %lu", context, desc,
                          (unsigned long) element);
    else
        webauth_error_set(ctx, status, "encoding %s", desc);
}


/*
 * Given an encoding specification, a data source, and an attribute list,
 * encode into attributes.  Takes a separate pool to use rather than using the
 * normal WebAuth context pool, since attribute encoding can churn a lot of
 * memory.  Context is a string to prepend to the description for error
 * reporting.  If element is non-zero, we are handling a repeated attribute
 * encoding, and the element number is appended to the attribute name when
 * encoding it.
 *
 * This is an internal helper function used by webauth_encode.
 */
static int
encode_to_attrs(struct webauth_context *ctx, apr_pool_t *pool,
                const struct webauth_encoding *rules, const void *input,
                WEBAUTH_ATTR_LIST *alist, const char *context,
                unsigned long element)
{
    const struct webauth_encoding *rule;
    const char *attr;
    unsigned long i;
    int status;
    void *data, *repeat;
    int32_t int32;
    char *string;
    size_t size;
    time_t time;
    uint32_t uint32;

    for (rule = rules; rule->attr != NULL; rule++) {
        if (element == 0)
            attr = rule->attr;
        else
            attr = apr_psprintf(pool, "%s%lu", rule->attr, element);
        switch (rule->type) {
        case WA_TYPE_DATA:
            data = *LOC_DATA(input, rule->offset);
            if (rule->optional && data == NULL)
                break;
            size = *LOC_SIZE(input, rule->len_offset);
            status = webauth_attr_list_add(alist, attr, data, size, WA_F_NONE);
            break;
        case WA_TYPE_STRING:
            string = *LOC_STRING(input, rule->offset);
            if (rule->optional && string == NULL)
                break;
            status = webauth_attr_list_add_str(alist, attr, string,
                                               strlen(string), WA_F_NONE);
            break;
        case WA_TYPE_INT32:
            int32 = *LOC_INT32(input, rule->offset);
            if (rule->optional && int32 == 0)
                break;
            status
                = webauth_attr_list_add_int32(alist, attr, int32, WA_F_NONE);
            break;
        case WA_TYPE_UINT32:
            uint32 = *LOC_UINT32(input, rule->offset);
            if (rule->optional && uint32 == 0)
                break;
            status
                = webauth_attr_list_add_uint32(alist, attr, uint32, WA_F_NONE);
            break;
        case WA_TYPE_TIME:
            time = *LOC_TIME(input, rule->offset);
            if (rule->optional && time == 0)
                break;
            status = webauth_attr_list_add_time(alist, attr, time, WA_F_NONE);
            break;
        case WA_TYPE_REPEAT:
            uint32 = *LOC_UINT32(input, rule->len_offset);
            if (rule->optional && uint32 == 0)
                break;
            status
                = webauth_attr_list_add_uint32(alist, attr, uint32, WA_F_NONE);
            if (status != WA_ERR_NONE)
                break;
            for (i = 0; i < uint32; i++) {
                repeat = *LOC_STRING(input, rule->offset) + rule->size * i;
                status = encode_to_attrs(ctx, pool, rule->repeat, repeat,
                                         alist, context, i);
                if (status != WA_ERR_NONE)
                    return status;
            }
            break;
        }
        if (status != WA_ERR_NONE) {
            encode_error_set(ctx, status, rule->desc, context, element);
            return status;
        }
    }
    return WA_ERR_NONE;
}


/*
 * Given an encoding specification and a pointer to the data to encode, encode
 * into attributes and return the encoded string in newly-allocated pool
 * memory.  Takes a separate pool to use rather than using the normal WebAuth
 * context pool, since attribute encoding can churn a lot of memory.
 *
 * FIXME: This currently still uses the underlying attribute code, but should
 * be split off into its own implementation and made independent of that.
 */
int
webauth_encode(struct webauth_context *ctx, apr_pool_t *pool,
               const struct webauth_encoding *rules,
               void *data, void **output, size_t *length)
{
    WEBAUTH_ATTR_LIST *alist;
    int status;
    size_t size;

    alist = webauth_attr_list_new(32);
    if (alist == NULL) {
        webauth_error_set(ctx, WA_ERR_NO_MEM, "creating attribute list");
        return WA_ERR_NO_MEM;
    }
    status = encode_to_attrs(ctx, pool, rules, data, alist, NULL, 0);
    if (status != WA_ERR_NONE)
        goto done;
    size = webauth_attrs_encoded_length(alist);
    *output = apr_palloc(pool, size);
    status = webauth_attrs_encode(alist, *output, length, size);
    if (status != WA_ERR_NONE)
        webauth_error_set(ctx, status, "encoding attributes");

done:
    webauth_attr_list_free(alist);
    return status;
}
