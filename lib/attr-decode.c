/*
 * Low-level attribute decoding.
 *
 * Provided here is a table-driven decoder that fills out the elements of a
 * struct from a WebAuth attribute encoding.  This is the encoding used inside
 * tokens and for some other WebAuth persistant data structures, such as
 * service token caches and keyrings.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <apr_hash.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>

#include <lib/internal.h>
#include <util/macros.h>
#include <webauth/basic.h>
#include <webauth/tokens.h>

/*
 * Stores metadata about a particular attribute in encoded data.  This is
 * stored as the value in a hash of attributes, with the key being the
 * attribute name.
 */
struct value {
    void *data;
    size_t length;
};

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
 * (for repeated elements).
 */
static void
decode_error_set(struct webauth_context *ctx, int s, const char *desc,
                 const char *context, size_t element)
{
    if (context != NULL && element != 0)
        wai_error_set(ctx, s, "decoding %s %s %lu", context, desc,
                      (unsigned long) element);
    else
        wai_error_set(ctx, s, "decoding %s", desc);
}


/*
 * Convert the attribute-encoded data to a hash table of attribute names to
 * values, where values are represented by struct value.  This destructively
 * modifies the encoded form in place to avoid having to make another copy of
 * the data.  Returns a WebAuth status code.
 */
static int
decode_attrs(struct webauth_context *ctx, void *data, size_t length,
             apr_hash_t **output)
{
    apr_hash_t *attrs;
    struct value *values;
    size_t i, n, offset;
    char *name, *value;
    size_t attr_count = 0;
    char *in = data;

    /*
     * First pass: count how many attributes there are.  Don't do any syntax
     * checking at this point.  Just count = signs that could be separators
     * between an attribute name and its value.
     */
    for (i = 0; i < length; i++) {
        if (in[i] == '=') {
            attr_count++;
            i++;
            while (i < length - 1) {
                if (in[i] == ';') {
                    if (in[i + 1] != ';')
                        break;
                    i++;
                }
                i++;
            }
        }
    }

    /*
     * We know roughly how many attributes there are.  Allocate data
     * structures.
     */
    attrs = apr_hash_make(ctx->pool);
    values = apr_pcalloc(ctx->pool, attr_count * sizeof(struct value));

    /*
     * Now, do the decoding.  As we go, we'll make two transformations:
     * nul-terminate the attribute name by replacing the = with a nul
     * character, and rewrite the value to unescape any semicolons.  When we
     * find the end of an attribute, we store it in the table.  This is where
     * we do all the syntax checking.
     */
    i = 0;
    n = 0;
    while (i < length) {
        name = in + i;

        /* Find the end of the attribute name. */
        while (i < length && in[i] != '=')
            i++;
        if (name == in + i || i >= length)
            goto corrupt;       /* no attribute name */
        in[i] = '\0';
        i++;

        /*
         * Find the end of the value, unescaping semicolons.  offset is how
         * much we have to shift each octet because of escaped semicolons
         * we've removed.
         */
        value = in + i;
        offset = 0;
        while (i < length) {
            if (in[i] == ';') {
                if (i < length - 1 && in[i + 1] == ';')
                    offset++;
                else
                    break;
                i++;
            }
            if (offset > 0)
                in[i - offset] = in[i];
            i++;
        }
        if (i >= length || in[i] != ';')
            goto corrupt;

        /* Check whether we have a duplicate. */
        if (apr_hash_get(attrs, name, strlen(name)) != NULL) {
            wai_error_set(ctx, WA_ERR_CORRUPT, "duplicate attribute %s", name);
            return WA_ERR_CORRUPT;
        }

        /*
         * We have a valid key/value pair.  Store it in the table and
         * nul-terminate in case it's a number encoded as a string to save us
         * some effort later.
         */
        in[i - offset] = '\0';
        values[n].data = value;
        values[n].length = (in + i) - value - offset;
        apr_hash_set(attrs, name, strlen(name), (const void *) &values[n]);
        n++;
        i++;
    }

    /* Success.  Store the table in our output variable and return. */
    *output = attrs;
    return WA_ERR_NONE;

corrupt:
    return wai_error_set(ctx, WA_ERR_CORRUPT, "invalid attribute data");
}


/*
 * Decode attribute data, possibly hex-encoded.  Takes the WebAuth context,
 * the value, the memory location to which to write the data, the memory
 * location to which to write the length, and a flag saying whether the value
 * is hex-encoded.  Returns a WebAuth error code.
 */
static int
decode_data(struct webauth_context *ctx, struct value *value, void **output,
            size_t *size, bool ascii)
{
    int s;
    size_t length;

    if (ascii) {
        s = wai_hex_decoded_length(value->length, &length);
        if (s != WA_ERR_NONE)
            return wai_error_set(ctx, s, "invalid hex-encoded data");
        *output = apr_pcalloc(ctx->pool, length);
        s = wai_hex_decode(value->data, value->length, *output, size, length);
        if (s != WA_ERR_NONE)
            return wai_error_set(ctx, s, "invalid hex-encoded data");
    } else {
        *output = apr_pmemdup(ctx->pool, value->data, value->length);
        *size = value->length;
    }
    return WA_ERR_NONE;
}


/*
 * Decode an attribute value as a string.  This is very similar to the
 * non-ascii case of decode_data, except that we nul-terminate the result.
 * Takes the WebAuth context, the value, and the location to which to write
 * the string.
 */
static void
decode_string(struct webauth_context *ctx, struct value *value, char **output)
{
    *output = apr_palloc(ctx->pool, value->length + 1);
    memcpy(*output, value->data, value->length);
    (*output)[value->length] = '\0';
}


/*
 * Decode an attribute value as a number.  All numbers are either encoded as
 * an ASCII string representing the number or as a network-byte-order 32-bit
 * unsigned number.  Signed results are by interpretation.  Therefore, takes
 * the WebAuth context, the value, a place to write the 32-bit unsigned value,
 * and a flag saying whether it was encoded as a string.
 */
static int
decode_number(struct webauth_context *ctx, struct value *value,
              uint32_t *output, bool ascii)
{
    char *end;
    uint32_t data;
    unsigned long n;

    if (ascii) {
        errno = 0;
        n = strtoul(value->data, &end, 10);
        if (*end != '\0' || (n == ULONG_MAX && errno != 0))
            goto corrupt;
        *output = n;
    } else {
        if (value->length != sizeof(uint32_t))
            goto corrupt;
        memcpy(&data, value->data, sizeof(uint32_t));
        *output = ntohl(data);
    }
    return WA_ERR_NONE;

corrupt:
    return wai_error_set(ctx, WA_ERR_CORRUPT, "invalid encoded number");
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
decode_by_rule(struct webauth_context *ctx, const struct wai_encoding *rules,
               apr_hash_t *attrs, const void *result, const char *context,
               unsigned long element)
{
    const struct wai_encoding *rule;
    const char *attr;
    struct value *value;
    unsigned long i;
    int s;
    void *data;
    void **repeat;
    uint32_t uint32;

    for (rule = rules; rule->attr != NULL; rule++) {
        if (context == NULL)
            attr = rule->attr;
        else
            attr = apr_psprintf(ctx->pool, "%s%lu", rule->attr, element);
        value = apr_hash_get(attrs, attr, strlen(attr));
        s = WA_ERR_NONE;

        /* If this attribute isn't optional, missing data is an error. */
        if (value == NULL) {
            if (rule->optional)
                continue;
            s = WA_ERR_CORRUPT;
            decode_error_set(ctx, s, rule->desc, context, element);
            return s;
        }
            
        /* Otherwise, interpret the value by data type. */
        switch (rule->type) {
        case WA_TYPE_DATA:
            s = decode_data(ctx, value, LOC_DATA(result, rule->offset),
                            LOC_SIZE(result, rule->len_offset), rule->ascii);
            break;
        case WA_TYPE_STRING:
            decode_string(ctx, value, LOC_STRING(result, rule->offset));
            break;
        case WA_TYPE_INT32:
            s = decode_number(ctx, value, &uint32, rule->ascii);
            if (s == WA_ERR_NONE)
                *LOC_INT32(result, rule->offset) = (int32_t) uint32;
            break;
        case WA_TYPE_UINT32:
            s = decode_number(ctx, value, &uint32, rule->ascii);
            if (s == WA_ERR_NONE)
                *LOC_UINT32(result, rule->offset) = uint32;
            break;
        case WA_TYPE_ULONG:
            s = decode_number(ctx, value, &uint32, rule->ascii);
            if (s == WA_ERR_NONE)
                *LOC_ULONG(result, rule->offset) = uint32;
            break;
        case WA_TYPE_TIME:
            s = decode_number(ctx, value, &uint32, rule->ascii);
            if (s == WA_ERR_NONE)
                *LOC_TIME(result, rule->offset) = (time_t) uint32;
            break;
        case WA_TYPE_REPEAT:
            s = decode_number(ctx, value, &uint32, rule->ascii);
            if (s != WA_ERR_NONE)
                break;
            *LOC_UINT32(result, rule->len_offset) = uint32;
            repeat = LOC_DATA(result, rule->offset);
            *repeat = apr_palloc(ctx->pool, rule->size * uint32);
            for (i = 0; i < uint32; i++) {
                data = (char *) *repeat + i * rule->size;
                s = decode_by_rule(ctx, rule->repeat, attrs, data, attr, i);
                if (s != WA_ERR_NONE)
                    return s;
            }
            break;
        }
        if (s != WA_ERR_NONE)
            return s;
    }
    return WA_ERR_NONE;
}


/*
 * Given an encoding specification, attribute-encoded data, and a data
 * structure, decode that data into the data structure as newly-allocated pool
 * memory.
 */
int
wai_decode(struct webauth_context *ctx, const struct wai_encoding *rules,
           const void *input, size_t length, void *data)
{
    apr_hash_t *attrs;
    int s;
    void *buf;

    buf = apr_pmemdup(ctx->pool, input, length);
    s = decode_attrs(ctx, buf, length, &attrs);
    if (s != WA_ERR_NONE)
        return s;
    return decode_by_rule(ctx, rules, attrs, data, NULL, 0);
}


/*
 * Similar to wai_decode, but decodes a WebAuth token, including handling the
 * determination of the type of the token from the attributes.  This does not
 * perform any sanity checking on the token data; that must be done by
 * higher-level code.
 */
int
wai_decode_token(struct webauth_context *ctx, const void *input,
                 size_t length, struct webauth_token *token)
{
    apr_hash_t *attrs;
    int s;
    void *buf, *data;
    struct value *value;
    char *type;
    const struct wai_encoding *rules;

    memset(token, 0, sizeof(*token));
    buf = apr_pmemdup(ctx->pool, input, length);
    s = decode_attrs(ctx, buf, length, &attrs);
    if (s != WA_ERR_NONE)
        return s;
    value = apr_hash_get(attrs, "t", strlen("t"));
    if (value == NULL)
        return wai_error_set(ctx, WA_ERR_CORRUPT, "no token type attribute");
    decode_string(ctx, value, &type);
    token->type = webauth_token_type_code(type);
    if (token->type == WA_TOKEN_UNKNOWN) {
        wai_error_set(ctx, WA_ERR_CORRUPT, "unknown token type %s", type);
        return WA_ERR_CORRUPT;
    }
    s = wai_token_encoding(ctx, token, &rules, (const void **) &data);
    if (s != WA_ERR_NONE)
        return s;
    return decode_by_rule(ctx, rules, attrs, data, NULL, 0);
}
