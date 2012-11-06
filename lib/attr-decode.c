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
#include <webauth/basic.h>
#include <webauth/tokens.h>

/*
 * Macros used to resolve a void * pointer to a struct and an offset into a
 * pointer to the appropriate type.  Scary violations of the C type system
 * lurk here.
 */
#define LOC_DATA(d, o)   (void **)         (void *)((char *) (d) + (o))
#define LOC_INT32(d, o)  (int32_t *)       (void *)((char *) (d) + (o))
#define LOC_STRING(d, o) (char **)         (void *)((char *) (d) + (o))
#define LOC_SIZE(d, o)   (size_t *)        (void *)((char *) (d) + (o))
#define LOC_TIME(d, o)   (time_t *)        (void *)((char *) (d) + (o))
#define LOC_UINT32(d, o) (uint32_t *)      (void *)((char *) (d) + (o))
#define LOC_ULONG(d, o)  (unsigned long *) (void *)((char *) (d) + (o))


/*
 * Report an error while encoding an attribute.  Takes the WebAuth context,
 * status, description, context (for repeated elements), and element number
 * (for repeated elements), and returns the new status (we may need to do
 * status code mapping).  This is an internal helper function for
 * decode_from_attrs.
 */
static int
decode_error_set(struct webauth_context *ctx, int status, const char *desc,
                 const char *context, size_t element)
{
    if (status == WA_ERR_NOT_FOUND)
        status = WA_ERR_CORRUPT;
    if (context != NULL && element != 0)
        wai_error_set(ctx, status, "decoding %s %s %lu", context, desc,
                      (unsigned long) element);
    else
        wai_error_set(ctx, status, "decoding %s", desc);
    return status;
}


/*
 * Given an encoding specification, an attribute list, and a data structure,
 * decode attributes into that data structure.  Takes a separate pool to use
 * rather than using the normal WebAuth context pool.  Context is a string to
 * prepend to the description for error reporting.  If element is non-zero, we
 * are handling a repeated attribute encoding, and the element number is
 * appended to the attribute name when decoding it.
 *
 * This is an internal helper function used by wai_decode.
 */
static int
decode_from_attrs(struct webauth_context *ctx, apr_pool_t *pool,
                  const struct wai_encoding *rules,
                  WEBAUTH_ATTR_LIST *alist, const void *result,
                  const char *context, unsigned long element)
{
    const struct wai_encoding *rule;
    const char *attr;
    unsigned long i;
    ssize_t index;
    int status, flags;
    void *data;
    void **repeat;
    int32_t int32;
    char *string;
    char **out;
    size_t size;
    time_t time;
    uint32_t uint32;

    for (rule = rules; rule->attr != NULL; rule++) {
        if (context == NULL)
            attr = rule->attr;
        else
            attr = apr_psprintf(pool, "%s%lu", rule->attr, element);
        if (rule->optional)
            if (webauth_attr_list_find(alist, attr, &index) != WA_ERR_NONE)
                continue;
        switch (rule->type) {
        case WA_TYPE_DATA:
            flags = rule->ascii ? WA_F_FMT_HEX : WA_F_NONE;
            status = webauth_attr_list_get(alist, attr, &data, &size, flags);
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
            flags = rule->ascii ? WA_F_FMT_STR : WA_F_NONE;
            status = webauth_attr_list_get_int32(alist, attr, &int32, flags);
            if (status != WA_ERR_NONE)
                break;
            *LOC_INT32(result, rule->offset) = int32;
            break;
        case WA_TYPE_UINT32:
            flags = rule->ascii ? WA_F_FMT_STR : WA_F_NONE;
            status = webauth_attr_list_get_uint32(alist, attr, &uint32, flags);
            if (status != WA_ERR_NONE)
                break;
            *LOC_UINT32(result, rule->offset) = uint32;
            break;
        case WA_TYPE_ULONG:
            flags = rule->ascii ? WA_F_FMT_STR : WA_F_NONE;
            status = webauth_attr_list_get_uint32(alist, attr, &uint32, flags);
            if (status != WA_ERR_NONE)
                break;
            *LOC_ULONG(result, rule->offset) = uint32;
            break;
        case WA_TYPE_TIME:
            flags = rule->ascii ? WA_F_FMT_STR : WA_F_NONE;
            status = webauth_attr_list_get_time(alist, attr, &time, flags);
            if (status != WA_ERR_NONE)
                break;
            *LOC_TIME(result, rule->offset) = time;
            break;
        case WA_TYPE_REPEAT:
            flags = rule->ascii ? WA_F_FMT_STR : WA_F_NONE;
            status = webauth_attr_list_get_uint32(alist, attr, &uint32, flags);
            if (status != WA_ERR_NONE)
                break;
            *LOC_UINT32(result, rule->len_offset) = uint32;
            repeat = LOC_DATA(result, rule->offset);
            *repeat = apr_palloc(pool, rule->size * uint32);
            for (i = 0; i < uint32; i++) {
                data = (char *) *repeat + i * rule->size;
                status = decode_from_attrs(ctx, pool, rule->repeat, alist,
                                           data, attr, i);
                if (status != WA_ERR_NONE)
                    return status;
            }
            break;
        }
        if (status != WA_ERR_NONE) {
            status = decode_error_set(ctx, status, rule->desc, context,
                                      element);
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
wai_decode(struct webauth_context *ctx, apr_pool_t *pool,
           const struct wai_encoding *rules, const void *input, size_t length,
           void *data)
{
    WEBAUTH_ATTR_LIST *alist;
    int status;
    void *buf;

    buf = apr_pmemdup(pool, input, length);
    status = webauth_attrs_decode(buf, length, &alist);
    if (status != WA_ERR_NONE) {
        wai_error_set(ctx, status, "decoding attributes");
        return status;
    }
    status = decode_from_attrs(ctx, pool, rules, alist, data, NULL, 0);
    webauth_attr_list_free(alist);
    return status;
}


/*
 * Similar to wai_decode, but decodes a WebAuth token, including handling the
 * determination of the type of the token from the attributes.  Uses the
 * memory pool from the WebAuth context.  This does not perform any sanity
 * checking on the token data; that must be done by higher-level code.
 */
int
wai_decode_token(struct webauth_context *ctx, const void *input,
                 size_t length, struct webauth_token *token)
{
    WEBAUTH_ATTR_LIST *alist;
    int status;
    void *buf, *data;
    char *type;
    size_t vlen;
    const struct wai_encoding *rules;

    memset(token, 0, sizeof(*token));
    buf = apr_pmemdup(ctx->pool, input, length);
    status = webauth_attrs_decode(buf, length, &alist);
    if (status != WA_ERR_NONE) {
        wai_error_set(ctx, status, "decoding attributes");
        return status;
    }
    status = webauth_attr_list_get_str(alist, "t", &type, &vlen, WA_F_NONE);
    if (status == WA_ERR_NOT_FOUND) {
        status = WA_ERR_CORRUPT;
        wai_error_set(ctx, status, "token has no type attribute");
        goto done;
    } else if (status != WA_ERR_NONE) {
        wai_error_set(ctx, status, "bad token");
        goto done;
    }
    token->type = webauth_token_type_code(type);
    if (token->type == WA_TOKEN_UNKNOWN) {
        status = WA_ERR_CORRUPT;
        wai_error_set(ctx, status, "unknown token type %s", type);
        goto done;
    }
    status = wai_token_encoding(ctx, token, &rules, (const void **) &data);
    if (status != WA_ERR_NONE)
        goto done;
    status = decode_from_attrs(ctx, ctx->pool, rules, alist, data, NULL, 0);

done:
    webauth_attr_list_free(alist);
    return status;
}
