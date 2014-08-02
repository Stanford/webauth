/*
 * WebKDC interface to retrieving user information.
 *
 * These interfaces are used by the WebKDC implementation to retrieve data
 * about a user from the user information service.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <apr_xml.h>
#include <errno.h>
#ifdef HAVE_JANSSON
# include <jansson.h>
#endif
#include <limits.h>
#ifdef HAVE_REMCTL
# include <remctl.h>
#endif
#include <time.h>

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/krb5.h>
#include <webauth/factors.h>
#include <webauth/webkdc.h>
#include <util/macros.h>

/* If remctl_set_ccache isn't available, pretend it always fails. */
#ifndef HAVE_REMCTL_SET_CCACHE
# define remctl_set_ccache(r, c) 0
#endif

/* If remctl_set_timeout isn't available, quietly do nothing. */
#ifndef HAVE_REMCTL_SET_TIMEOUT
# define remctl_set_timeout(r, t) /* empty */
#endif


/*
 * Helper function to apr_pstrdup a string if non-NULL or return NULL if the
 * string is NULL.
 */
static const char *
pstrdup_null(apr_pool_t *pool, const char *string)
{
    if (string == NULL)
        return string;
    else
        return apr_pstrdup(pool, string);
}


/*
 * Configure how to access the user information service.  Takes the method,
 * the host, an optional port (may be 0 to use the default for that method),
 * an optional authentication identity for the remote service (may be NULL to
 * use the default for that method), and a method-specific command parameter
 * such as a remctl command name or a partial URL.  The configuration
 * information is stored in the WebAuth context and used for all subsequent
 * webauth_userinfo queries.
 */
int
webauth_user_config(struct webauth_context *ctx,
                    const struct webauth_user_config *user)
{
    int s = WA_ERR_NONE;

    /* Verify that the new configuration is sane. */
    if (user->protocol != WA_PROTOCOL_REMCTL) {
        s = WA_ERR_UNIMPLEMENTED;
        wai_error_set(ctx, s, "unknown protocol %d", user->protocol);
        goto done;
    }
    if (user->host == NULL) {
        s = WA_ERR_INVALID;
        wai_error_set(ctx, s, "user information host must be set");
        goto done;
    }
    if (user->protocol == WA_PROTOCOL_REMCTL && user->keytab == NULL) {
        s = WA_ERR_INVALID;
        wai_error_set(ctx, s, "keytab must be configured for remctl protocol");
        goto done;
    }

    /* If JSON is requested, verify that we were built with JSON support. */
#ifndef HAVE_JANSSON
    if (user->json) {
        s = WA_ERR_UNIMPLEMENTED;
        wai_error_set(ctx, s, "not built with JSON support");
        goto done;
    }
#endif

    /* Copy the configuration into the context. */
    ctx->user = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_config));
    ctx->user->protocol       = user->protocol;
    ctx->user->host           = apr_pstrdup(ctx->pool, user->host);
    ctx->user->port           = user->port;
    ctx->user->identity       = pstrdup_null(ctx->pool, user->identity);
    ctx->user->command        = pstrdup_null(ctx->pool, user->command);
    ctx->user->keytab         = pstrdup_null(ctx->pool, user->keytab);
    ctx->user->principal      = pstrdup_null(ctx->pool, user->principal);
    ctx->user->timeout        = user->timeout;
    ctx->user->ignore_failure = user->ignore_failure;
    ctx->user->json           = user->json;

done:
    return s;
}


/*
 * Convert a number in an XML document from a string to a number, storing it
 * in the provided variable.  Returns a status code.
 */
static int UNUSED
convert_number(struct webauth_context *ctx, const char *string,
               unsigned long *value)
{
    int s;
    char *end;

    errno = 0;
    *value = strtoul(string, &end, 10);
    if (*end != '\0' || (*value == ULONG_MAX && errno != 0)) {
        s = WA_ERR_REMOTE_FAILURE;
        return wai_error_set(ctx, s, "invalid number %s in XML", string);
    }
    return WA_ERR_NONE;
}


/*
 * Parse the factors or persistent-factors sections of a userinfo XML
 * document.  Stores the results in the provided factors struct.  If
 * expiration is non-NULL, accept and parse a user expiration time into that
 * time_t pointer.  If valid_threshold is non-NULL, accept and parse a cutoff
 * time into that time_t pointer.  Returns a status code.
 */
static int UNUSED
xml_parse_factors(struct webauth_context *ctx, apr_xml_elem *root,
                  const struct webauth_factors **result, time_t *expiration,
                  time_t *valid_threshold)
{
    apr_xml_elem *child;
    apr_array_header_t *factors = NULL;
    const char **type, *content;
    unsigned long value;
    int s;

    /* Ensure the output variables are initialized in case of error. */
    if (result != NULL)
        *result = NULL;
    if (expiration != NULL)
        *expiration = 0;
    if (valid_threshold != NULL)
        *valid_threshold = 0;

    /* Parse the XML element and store the results. */
    for (child = root->first_child; child != NULL; child = child->next) {
        if (strcmp(child->name, "factor") == 0) {
            if (result == NULL)
                continue;
            if (factors == NULL)
                factors = apr_array_make(ctx->pool, 2, sizeof(const char *));
            type = apr_array_push(factors);
            s = wai_xml_content(ctx, child, type);
            if (s != WA_ERR_NONE)
                return s;
        } else if (strcmp(child->name, "expiration") == 0) {
            if (expiration == NULL)
                continue;
            s = wai_xml_content(ctx, child, &content);
            if (s == WA_ERR_NONE) {
                s = convert_number(ctx, content, &value);
                *expiration = value;
            }
            if (s != WA_ERR_NONE)
                return s;
        } else if (strcmp(child->name, "valid-threshold") == 0) {
            if (valid_threshold == NULL)
                continue;
            s = wai_xml_content(ctx, child, &content);
            if (s == WA_ERR_NONE) {
                s = convert_number(ctx, content, &value);
                *valid_threshold = value;
            }
            if (s != WA_ERR_NONE)
                return s;
        }
    }

    /* Save the factors if we found any and the caller wants them. */
    if (factors != NULL && result != NULL)
        *result = webauth_factors_new(ctx, factors);

    /* FIXME: Warn if expiration != NULL but no expiration was found. */
    return WA_ERR_NONE;
}


/*
 * Parse the login history section of a userinfo XML document.  Stores the
 * results in the provided array.  Returns a status code.
 */
static int UNUSED
xml_parse_history(struct webauth_context *ctx, apr_xml_elem *root,
                  const apr_array_header_t **result)
{
    apr_xml_elem *child;
    apr_xml_attr *attr;
    apr_array_header_t *logins = NULL;
    struct webauth_login *login;
    int s;
    size_t size;
    unsigned long timestamp;

    for (child = root->first_child; child != NULL; child = child->next) {
        if (strcmp(child->name, "host") != 0)
            continue;
        if (logins == NULL) {
            size = sizeof(struct webauth_login);
            logins = apr_array_make(ctx->pool, 5, size);
        }
        login = apr_array_push(logins);
        s = wai_xml_content(ctx, child, &login->ip);
        if (s != WA_ERR_NONE)
            return s;
        for (attr = child->attr; attr != NULL; attr = attr->next)
            if (strcmp(attr->name, "name") == 0)
                login->hostname = attr->value;
            else if (strcmp(attr->name, "timestamp") == 0) {
                s = convert_number(ctx, attr->value, &timestamp);
                if (s != WA_ERR_NONE)
                    return s;
                login->timestamp = timestamp;
            }
    }
    *result = logins;
    return WA_ERR_NONE;
}


/*
 * Given an XML document returned by the webkdc-userinfo call, however
 * obtained, finish parsing it into a newly-allocated webauth_user_info
 * struct.  This function and all of the functions it calls intentionally
 * ignores unknown XML elements or attributes.  Returns a status code.
 */
static int UNUSED
xml_parse_user_info(struct webauth_context *ctx, apr_xml_doc *doc,
                    struct webauth_user_info **result)
{
    apr_xml_elem *child;
    int s = WA_ERR_REMOTE_FAILURE;
    struct webauth_user_info *info;
    unsigned long value;
    const char *content;
    bool multifactor_required = false;

    /* We currently don't check that the user parameter is correct. */
    if (strcmp(doc->root->name, "authdata") != 0)
        return wai_error_set(ctx, s, "root element is %s, not authdata",
                             doc->root->name);

    /* Parse the XML. */
    info = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_info));
    for (child = doc->root->first_child; child != NULL; child = child->next) {
        s = WA_ERR_NONE;
        if (strcmp(child->name, "error") == 0)
            s = wai_xml_content(ctx, child, &info->error);
        else if (strcmp(child->name, "factors") == 0)
            s = xml_parse_factors(ctx, child, &info->factors, NULL, NULL);
        else if (strcmp(child->name, "additional-factors") == 0)
            s = xml_parse_factors(ctx, child, &info->additional, NULL, NULL);
        else if (strcmp(child->name, "multifactor-required") == 0)
            multifactor_required = true;
        else if (strcmp(child->name, "required-factors") == 0)
            s = xml_parse_factors(ctx, child, &info->required, NULL, NULL);
        else if (strcmp(child->name, "persistent-factors") == 0)
            s = xml_parse_factors(ctx, child, NULL, NULL,
                                  &info->valid_threshold);
        else if (strcmp(child->name, "login-history") == 0)
            s = xml_parse_history(ctx, child, &info->logins);
        else if (strcmp(child->name, "max-loa") == 0) {
            s = wai_xml_content(ctx, child, &content);
            if (s == WA_ERR_NONE)
                s = convert_number(ctx, content, &info->max_loa);
        } else if (strcmp(child->name, "password-expires") == 0) {
            s = wai_xml_content(ctx, child, &content);
            if (s == WA_ERR_NONE) {
                s = convert_number(ctx, content, &value);
                info->password_expires = value;
            }
        } else if (strcmp(child->name, "user-message") == 0)
            s = wai_xml_content(ctx, child, &info->user_message);
        else if (strcmp(child->name, "login-state") == 0)
            s = wai_xml_content(ctx, child, &info->login_state);
        if (s != WA_ERR_NONE)
            return s;
    }

    /*
     * For backwards compatibility, if <multifactor-required /> was present
     * but not <required-factors>, add m as a required factor.
     */
    if (info->required == NULL && multifactor_required)
        info->required = webauth_factors_parse(ctx, WA_FA_MULTIFACTOR);

    /* Return the results. */
    *result = info;
    return WA_ERR_NONE;
}


/*
 * Given an XML document returned by the webkdc-validate call, however
 * obtained, finish parsing it into a newly-allocated webauth_user_validate
 * struct.  This function and all of the functions it calls intentionally
 * ignores unknown XML elements or attributes.  Returns a status code.
 */
static int UNUSED
xml_parse_user_validate(struct webauth_context *ctx, apr_xml_doc *doc,
                        struct webauth_user_validate **result)
{
    apr_xml_elem *child;
    int s = WA_ERR_REMOTE_FAILURE;
    struct webauth_user_validate *validate;
    const char *content;

    if (strcmp(doc->root->name, "authdata") != 0)
        return wai_error_set(ctx, s, "root element is %s, not authdata",
                             doc->root->name);
    validate = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_validate));
    for (child = doc->root->first_child; child != NULL; child = child->next) {
        if (strcmp(child->name, "success") == 0) {
            s = wai_xml_content(ctx, child, &content);
            if (s == WA_ERR_NONE)
                validate->success = (strcmp(content, "yes") == 0);
        } else if (strcmp(child->name, "factors") == 0)
            s = xml_parse_factors(ctx, child, &validate->factors,
                                  &validate->factors_expiration, NULL);
        else if (strcmp(child->name, "persistent-factors") == 0)
            s = xml_parse_factors(ctx, child, &validate->persistent,
                                  &validate->persistent_expiration,
                                  &validate->valid_threshold);
        else if (strcmp(child->name, "loa") == 0) {
            s = wai_xml_content(ctx, child, &content);
            if (s == WA_ERR_NONE)
                s = convert_number(ctx, content, &validate->loa);
        } else if (strcmp(child->name, "user-message") == 0)
            s = wai_xml_content(ctx, child, &validate->user_message);
        else if (strcmp(child->name, "login-state") == 0)
            s = wai_xml_content(ctx, child, &validate->login_state);
        if (s != WA_ERR_NONE)
            return s;
    }
    *result = validate;
    return WA_ERR_NONE;
}


/*
 * Given an XML document in a struct wai_buffer, parse it into an apr_xml_doc
 * structure and store it in the provided argument.  If the parse fails, set
 * the WebAuth error and return a status code.
 */
static int UNUSED
xml_parse_document(struct webauth_context *ctx, struct wai_buffer *string,
                   apr_xml_doc **doc)
{
    apr_xml_parser *parser = NULL;
    apr_status_t code;
    char errbuf[BUFSIZ] = "";
    int s;

    /* Create a parser and feed it the string. */
    parser = apr_xml_parser_create(ctx->pool);
    code = apr_xml_parser_feed(parser, string->data, string->used);
    if (code != APR_SUCCESS) {
        apr_xml_parser_geterror(parser, errbuf, sizeof(errbuf));
        s = wai_error_set(ctx, WA_ERR_REMOTE_FAILURE, "XML error: %s", errbuf);
        goto fail;
    }

    /* Finish the parse and store the results in doc. */
    code = apr_xml_parser_done(parser, doc);
    if (code != APR_SUCCESS) {
        apr_xml_parser_geterror(parser, errbuf, sizeof(errbuf));
        s = wai_error_set(ctx, WA_ERR_REMOTE_FAILURE, "XML error: %s", errbuf);
        return s;
    }
    return WA_ERR_NONE;

fail:
    if (parser != NULL)
        apr_xml_parser_done(parser, NULL);
    return s;
}


/*
 * Given a WebAuth context, a JSON object, a key, and storage for an unsigned
 * long, retrieve the value of that key as an integer and store it in the
 * provided location.  If the key is not present or is null, leave result
 * alone and return success.  If the key is present but the value is not an
 * integer or is too long for an unsigned long, return an error code.
 */
#ifdef HAVE_JANSSON
static int
json_parse_integer(struct webauth_context *ctx, json_t *json, const char *key,
                   unsigned long *result)
{
    json_t *value;
    json_int_t integer;
    int s = WA_ERR_REMOTE_FAILURE;

    value = json_object_get(json, key);
    if (value == NULL || json_is_null(value))
        return WA_ERR_NONE;
    if (!json_is_integer(value))
        return wai_error_set(ctx, s, "value of %s is not an integer", key);
    integer = json_integer_value(value);
    if (integer < 0 || integer > ULONG_MAX)
        return wai_error_set(ctx, s, "value of %s (%" JSON_INTEGER_FORMAT
                             ") is out of range", key, integer);
    *result = integer;
    return WA_ERR_NONE;
}
#endif /* HAVE_JANSSON */


/*
 * Given a WebAuth context, a JSON object, a key, and storage for an unsigned
 * long, retrieve the value of that key as a string and store a pool copy of
 * it in the provided location.  If the key is not present or is null, leave
 * result alone and return success.  If the key is present but the value is
 * not an integer or is too long for an unsigned long, return an error code.
 */
#ifdef HAVE_JANSSON
static int
json_parse_string(struct webauth_context *ctx, json_t *json, const char *key,
                  const char **result)
{
    json_t *value;
    int s = WA_ERR_REMOTE_FAILURE;

    value = json_object_get(json, key);
    if (value == NULL || json_is_null(value))
        return WA_ERR_NONE;
    if (!json_is_string(value))
        return wai_error_set(ctx, s, "value of %s is not a string", key);
    *result = apr_pstrdup(ctx->pool, json_string_value(value));
    return WA_ERR_NONE;
}
#endif /* HAVE_JANSSON */


/*
 * Parse factors from a JSON document, given an object and a key in that
 * object.  The factors may be present in two different forms: a simple list
 * of strings, or a list of objects with keys factor and expiration.  If
 * expiration information is present, and the expiration pointer is non-NULL,
 * the lowest expiration is stored in that pointer.  Returns a status code.
 */
#ifdef HAVE_JANSSON
static int UNUSED
json_parse_factors(struct webauth_context *ctx, json_t *json, const char *key,
                   const struct webauth_factors **result, time_t *expiration)
{
    json_t *value, *array;
    apr_array_header_t *factors = NULL;
    const char **factor;
    unsigned long expires, min_expires = 0;
    size_t i;
    int s;

    /* Ensure the output variables are initialized in case of error. */
    if (result != NULL)
        *result = NULL;
    if (expiration != NULL)
        *expiration = 0;

    /* Get the array of factors. */
    array = json_object_get(json, key);
    if (array == NULL || json_is_null(array))
        return WA_ERR_NONE;
    if (!json_is_array(array)) {
        s = WA_ERR_REMOTE_FAILURE;
        return wai_error_set(ctx, s, "value of %s is not an array", key);
    }

    /* Walk the array looking for strings or objects. */
    for (i = 0; i < json_array_size(array); i++) {
        value = json_array_get(array, i);
        if (factors == NULL)
            factors = apr_array_make(ctx->pool, 2, sizeof(const char *));
        factor = apr_array_push(factors);
        if (json_is_string(value))
            *factor = apr_pstrdup(ctx->pool, json_string_value(value));
        else if (json_is_object(value)) {
            s = json_parse_string(ctx, value, "factor", factor);
            if (s != WA_ERR_NONE)
                return s;
            expires = 0;
            s = json_parse_integer(ctx, value, "expiration", &expires);
            if (s != WA_ERR_NONE)
                return s;
            if (expires > 0 && expires < min_expires)
                min_expires = expires;
        } else {
            s = WA_ERR_REMOTE_FAILURE;
            return wai_error_set(ctx, s, "%s element is not string or object",
                                 key);
        }
    }

    /* Save the factors if we found any and the caller wants them. */
    if (factors != NULL && result != NULL)
        *result = webauth_factors_new(ctx, factors);

    /* Save the minimum expiration time if the caller wants it. */
    if (expiration != NULL)
        *expiration = min_expires;

    /* FIXME: Warn if expiration != NULL but no expiration was found. */
    return WA_ERR_NONE;
}
#endif /* HAVE_JANSSON */


/*
 * Parse the logins section of a userinfo JSON document.  Stores the results
 * in the provided array.  Returns a status code.
 */
#ifdef HAVE_JANSSON
static int UNUSED
json_parse_history(struct webauth_context *ctx, json_t *json, const char *key,
                   const apr_array_header_t **result)
{
    json_t *value, *array;
    unsigned long timestamp;
    apr_array_header_t *logins = NULL;
    struct webauth_login *login;
    int s = WA_ERR_REMOTE_FAILURE;
    size_t size, i;

    /* Get the array of factors. */
    array = json_object_get(json, key);
    if (array == NULL || json_is_null(array))
        return WA_ERR_NONE;
    if (!json_is_array(array))
        return wai_error_set(ctx, s, "value of %s is not an array", key);

    /* Walk the array looking for objects. */
    for (i = 0; i < json_array_size(array); i++) {
        value = json_array_get(array, i);
        if (!json_is_object(value))
            return wai_error_set(ctx, s, "%s element is not object", key);
        if (logins == NULL) {
            size = sizeof(struct webauth_login);
            logins = apr_array_make(ctx->pool, 5, size);
        }
        login = apr_array_push(logins);
        memset(login, 0, sizeof(*login));
        s = json_parse_string(ctx, value, "ip", &login->ip);
        if (s != WA_ERR_NONE)
            return s;
        if (login->ip == NULL) {
            s = WA_ERR_REMOTE_FAILURE;
            return wai_error_set(ctx, s, "%s element has no ip key", key);
        }
        s = json_parse_integer(ctx, value, "timestamp", &timestamp);
        if (s != WA_ERR_NONE)
            return s;
        login->timestamp = timestamp;
        s = json_parse_string(ctx, value, "hostname", &login->hostname);
        if (s != WA_ERR_NONE)
            return s;
    }

    /* Return the results. */
    *result = logins;
    return WA_ERR_NONE;
}
#endif /* HAVE_JANSSON */


/*
 * Given JSON returned by the webkdc-userinfo call, finish parsing it into a
 * newly-allocated webauth_user_info struct.  This function and all of the
 * functions it calls intentionally ignores unknown JSON attributes.  Returns
 * a status code.
 */
#ifdef HAVE_JANSSON
static int UNUSED
json_parse_user_info(struct webauth_context *ctx, json_t *json,
                     struct webauth_user_info **result)
{
    const char *message, *detail;
    unsigned long code, timestamp;
    json_t *value, *object;
    int s = WA_ERR_REMOTE_FAILURE;
    struct webauth_user_info *info;

    /* Check for the success key. */
    value = json_object_get(json, "success");
    if (value == NULL)
        return wai_error_set(ctx, s, "no success key in JSON");

    /* Create the data structure for the reply and pull out login_state. */
    info = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_info));
    s = json_parse_string(ctx, json, "login_state", &info->login_state);
    if (s != WA_ERR_NONE)
        return s;

    /*
     * If validation failed, return the message_detail string as the user
     * message if it is set.  If it is not set, report an internal error using
     * the message and the code.
     */
    if (json_is_false(value)) {
        s = json_parse_integer(ctx, json, "code", &code);
        if (s == WA_ERR_NONE)
            s = json_parse_string(ctx, json, "message", &message);
        if (s == WA_ERR_NONE)
            s = json_parse_string(ctx, json, "message_detail", &detail);
        if (s != WA_ERR_NONE)
            return s;
        if (detail == NULL)
            return wai_error_set(ctx, s, "%s [%lu]", message, code);
        else {
            wai_log_notice(ctx, "userinfo: webkdc-userinfo failed: %s [%lu]",
                           message, code);
            info->user_message = detail;
            *result = info;
            return WA_ERR_NONE;
        }
    }

    /* Grab the result key, which contains the meat of the reply. */
    object = json_object_get(json, "result");
    if (object == NULL || !json_is_object(object))
        return wai_error_set(ctx, s, "no or malformed result key in JSON");

    /*
     * User info succeeded.  Pull the data out of the JSON reply.
     *
     * FIXME: This really needs to be rewritten to be table-driven, or use
     * macros, or otherwise made somehow not so ugly and hard to read.
     */
    s = json_parse_integer(ctx, object, "persistent_threshold", &timestamp);

    if (s != WA_ERR_NONE)
        return s;
    info->valid_threshold = timestamp;
    s = json_parse_integer(ctx, object, "password_expires", &timestamp);
    if (s != WA_ERR_NONE)
        return s;
    info->password_expires = timestamp;
    s = json_parse_integer(ctx, object, "max_level_of_assurance",
                           &info->max_loa);
    if (s != WA_ERR_NONE)
        return s;
    s = json_parse_factors(ctx, object, "available_factors", &info->factors,
                           NULL);
    if (s != WA_ERR_NONE)
        return s;
    s = json_parse_factors(ctx, object, "additional_factors",
                           &info->additional, NULL);
    if (s != WA_ERR_NONE)
        return s;
    s = json_parse_factors(ctx, object, "required_factors", &info->required,
                           NULL);
    if (s != WA_ERR_NONE)
        return s;
    s = json_parse_history(ctx, object, "logins", &info->logins);
    if (s != WA_ERR_NONE)
        return s;

    /* Return the results. */
    *result = info;
    return WA_ERR_NONE;
}
#endif /* HAVE_JANSSON */


/*
 * Given JSON returned by the webkdc-validate call, finish parsing it into a
 * newly-allocated webauth_user_validate struct.  This function and all of the
 * functions it calls intentionally ignores unknown JSON attributes.  Returns
 * a status code.
 */
#ifdef HAVE_JANSSON
static int UNUSED
json_parse_user_validate(struct webauth_context *ctx, json_t *json,
                         struct webauth_user_validate **result)
{
    const char *message, *detail;
    unsigned long code, timestamp;
    json_t *value, *object;
    int s = WA_ERR_REMOTE_FAILURE;
    struct webauth_user_validate *validate;

    /* Check for the success key. */
    value = json_object_get(json, "success");
    if (value == NULL)
        return wai_error_set(ctx, s, "no success key in JSON");

    /* Create the data structure for the reply. */
    validate = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_validate));
    s = json_parse_string(ctx, json, "login_state", &validate->login_state);
    if (s != WA_ERR_NONE)
        return s;

    /*
     * If validation failed, return the message_detail string as the user
     * message if it is set.  If it is not set, report an internal error using
     * the message and the code.
     */
    if (json_is_false(value)) {
        s = json_parse_integer(ctx, json, "code", &code);
        if (s == WA_ERR_NONE)
            s = json_parse_string(ctx, json, "message", &message);
        if (s == WA_ERR_NONE)
            s = json_parse_string(ctx, json, "message_detail", &detail);
        if (s != WA_ERR_NONE)
            return s;
        if (detail == NULL)
            return wai_error_set(ctx, s, "%s [%lu]", message, code);
        else {
            wai_log_notice(ctx, "userinfo: webkdc-validate failed: %s [%lu]",
                           message, code);
            validate->user_message = detail;
            *result = validate;
            return WA_ERR_NONE;
        }
    }

    /* Grab the result key, which contains the meat of the reply. */
    object = json_object_get(json, "result");
    if (object == NULL || !json_is_object(object))
        return wai_error_set(ctx, s, "no or malformed result key in JSON");

    /*
     * Validation succeeded.  Pull the data out of the JSON reply.
     *
     * FIXME: This really needs to be rewritten to be table-driven, or use
     * macros, or otherwise made somehow not so ugly and hard to read.
     */
    s = json_parse_integer(ctx, object, "persistent_threshold", &timestamp);
    if (s != WA_ERR_NONE)
        return s;
    validate->valid_threshold = timestamp;
    s = json_parse_integer(ctx, object, "level_of_assurance", &validate->loa);
    if (s != WA_ERR_NONE)
        return s;
    s = json_parse_string(ctx, object, "message", &validate->user_message);
    if (s != WA_ERR_NONE)
        return s;
    s = json_parse_factors(ctx, object, "factors", &validate->factors,
                           &validate->factors_expiration);
    if (s != WA_ERR_NONE)
        return s;
    s = json_parse_factors(ctx, object, "persistent_factors",
                           &validate->persistent,
                           &validate->persistent_expiration);
    if (s != WA_ERR_NONE)
        return s;

    /* Return the results. */
    *result = validate;
    return WA_ERR_NONE;
}
#endif /* HAVE_JANSSON */


/*
 * Given an JSON document in a struct wai_buffer, parse it into a json_t
 * structure and store it in the provided argument.  The contents of the
 * buffer must be nul-terminated.  The caller is responsible for decrementing
 * the reference count on the json_t object when finished with it.
 *
 * If the parse fails, set the WebAuth error and return a status code.
 */
#ifdef HAVE_JANSSON
static int UNUSED
json_parse_document(struct webauth_context *ctx, struct wai_buffer *string,
                    json_t **json)
{
    json_error_t error;
    int s;

    *json = json_loads(string->data, 0, &error);
    if (*json == NULL) {
        s = wai_error_set(ctx, WA_ERR_REMOTE_FAILURE,
                          "JSON parse error: %s at byte %lu",
                          error.text, (unsigned long) error.position);
        return s;
    }
    return WA_ERR_NONE;
}
#endif /* HAVE_JANSSON */


/*
 * Issue a remctl command to the user information service.  Takes the
 * argv-style vector of the command to execute and a timeout (which may be 0
 * to use no timeout), and stores the resulting output in the provided
 * argument.  On any error, including remote failure to execute the command,
 * sets the WebAuth error and returns a status code.
 */
#ifdef HAVE_REMCTL
static int
remctl_generic(struct webauth_context *ctx, const char **command,
               struct wai_buffer *output)
{
    struct remctl *r = NULL;
    struct remctl_output *out;
    size_t offset;
    struct wai_buffer *errors, *buffer;
    struct webauth_user_config *c = ctx->user;
    struct webauth_krb5 *kc = NULL;
    char *cache;
    int s;

    /* Initialize the remctl context. */
    r = remctl_new();
    if (r == NULL) {
        s = WA_ERR_NO_MEM;
        return wai_error_set_system(ctx, s, errno, "initializing remctl");
    }

    /*
     * Obtain authentication credentials from the configured keytab and
     * principal.
     *
     * This changes the global GSS-API state to point to our ticket cache.
     * Unfortunately, the GSS-API doesn't currently provide any way to avoid
     * this.  When there is some way, it will be implemented in remctl.
     *
     * If remctl_set_ccache fails or doesn't exist, we fall back on just
     * whacking the global KRB5CCNAME variable.
     */
    s = webauth_krb5_new(ctx, &kc);
    if (s != WA_ERR_NONE)
        goto fail;
    s = webauth_krb5_init_via_keytab(ctx, kc, c->keytab, c->principal, NULL);
    if (s != WA_ERR_NONE)
        goto fail;
    s = webauth_krb5_get_cache(ctx, kc, &cache);
    if (s != WA_ERR_NONE)
        goto fail;
    if (!remctl_set_ccache(r, cache)) {
        if (setenv("KRB5CCNAME", cache, 1) < 0) {
            s = WA_ERR_NO_MEM;
            wai_error_set_system(ctx, s, errno,
                                 "setting KRB5CCNAME for remctl");
            goto fail;
        }
    }

    /* Set a timeout if one was given. */
    if (c->timeout > 0)
        remctl_set_timeout(r, c->timeout);

    /* Set up and execute the command. */
    if (c->command == NULL) {
        s = WA_ERR_INVALID;
        wai_error_set(ctx, s, "no remctl command specified");
        goto fail;
    }
    if (!remctl_open(r, c->host, c->port, c->identity)) {
        s = WA_ERR_REMOTE_FAILURE;
        wai_error_set(ctx, s, "%s", remctl_error(r));
        goto fail;
    }
    if (!remctl_command(r, command)) {
        s = WA_ERR_REMOTE_FAILURE;
        wai_error_set(ctx, s, "%s", remctl_error(r));
        goto fail;
    }

    /*
     * Retrieve the results and accumulate output in the output buffer.
     * Accumulate errors in the errors variable, although we ignore that
     * stream unless the exit status is non-zero.
     */
    errors = wai_buffer_new(ctx->pool);
    do {
        out = remctl_output(r);
        if (out == NULL) {
            s = WA_ERR_REMOTE_FAILURE;
            wai_error_set(ctx, s, "%s", remctl_error(r));
            goto fail;
        }
        switch (out->type) {
        case REMCTL_OUT_OUTPUT:
            buffer = (out->stream == 1) ? output : errors;
            wai_buffer_append(buffer, out->data, out->length);
            break;
        case REMCTL_OUT_ERROR:
            s = WA_ERR_REMOTE_FAILURE;
            wai_buffer_set(errors, out->data, out->length);
            wai_error_set(ctx, s, "%s", errors->data);
            goto fail;
        case REMCTL_OUT_STATUS:
            if (out->status != 0) {
                if (errors->data == NULL)
                    wai_buffer_append_sprintf(errors,
                                              "program exited with status %d",
                                              out->status);
                if (wai_buffer_find_string(errors, "\n", 0, &offset))
                    errors->data[offset] = '\0';
                s = WA_ERR_REMOTE_FAILURE;
                wai_error_set(ctx, s, "%s", errors->data);
                goto fail;
            }
        case REMCTL_OUT_DONE:
        default:
            break;
        }
    } while (out->type == REMCTL_OUT_OUTPUT);
    remctl_close(r);
    r = NULL;
    return WA_ERR_NONE;

fail:
    if (r != NULL)
        remctl_close(r);
    return s;
}
#else /* !HAVE_REMCTL */
static int
remctl_generic(struct webauth_context *ctx, const char **command UNUSED,
               apr_xml_doc **doc UNUSED)
{
    return wai_error_set(ctx, WA_ERR_UNIMPLEMENTED,
                         "not built with remctl support");
}
#endif /* !HAVE_REMCTL */


/*
 * Call the user information service via remctl and parse the results into a
 * webauth_user_info struct.
 */
static int
remctl_info(struct webauth_context *ctx, const char *user, const char *ip,
            int random_mf, const char *url, const char *factors_string,
            struct webauth_user_info **info)
{
    int s;
    const char *argv[9];
    struct wai_buffer *output;
    struct webauth_user_config *c = ctx->user;
#ifdef HAVE_JANSSON
    json_t *json = NULL;
#endif

    /*
     * Build the command.
     *
     * FIXME: The JSON code here is horrible and needs some better structure.
     * It will also leak memory if there is some failure adding the temporary
     * objects since those objects aren't decref'd.
     */
    argv[0] = c->command;
    argv[1] = "webkdc-userinfo";
    if (c->json) {
#ifdef HAVE_JANSSON
        json_t *value, *member;
        struct webauth_factors *factors;
        apr_array_header_t *factors_array;
        const char *factor;
        int i;

        json = json_object();
        if (json == NULL)
            goto fail;
        value = json_string(user);
        if (value == NULL)
            goto fail;
        if (json_object_set_new(json, "username", value) < 0)
            goto fail;
        if (ip != NULL) {
            value = json_string(ip);
            if (value == NULL)
                goto fail;
            if (json_object_set_new(json, "ip", value) < 0)
                goto fail;
        }
        value = json_integer(time(NULL));
        if (value == NULL)
            goto fail;
        if (json_object_set_new(json, "timestamp", value) < 0)
            goto fail;
        if (json_object_set_new(json, "random", json_boolean(random_mf)) < 0)
            goto fail;
        if (url != NULL) {
            value = json_string(url);
            if (value == NULL)
                goto fail;
            if (json_object_set_new(json, "return_url", value) < 0)
                goto fail;
        }
        value = json_array();
        factors = webauth_factors_parse(ctx, factors_string);
        factors_array = webauth_factors_array(ctx, factors);
        for (i = 0; i < factors_array->nelts; i++) {
            factor = APR_ARRAY_IDX(factors_array, i, const char *);
            member = json_string(factor);
            if (member == NULL)
                goto fail;
            if (json_array_append_new(value, member) < 0)
                goto fail;
        }
        if (json_object_set_new(json, "factors", value) < 0)
            goto fail;
        argv[2] = json_dumps(json, 0);
        if (argv[2] == NULL)
            goto fail;
        argv[3] = NULL;
        json_decref(json);
#else /* !HAVE_JANSSON */
        s = WA_ERR_UNIMPLEMENTED;
        return wai_error_set(ctx, s, "not built with JSON support");
#endif
    } else {
        if (url == NULL && factors_string != NULL)
            url = "";
        argv[2] = user;
        argv[3] = ip;
        argv[4] = apr_psprintf(ctx->pool, "%lu", (unsigned long) time(NULL));
        argv[5] = apr_psprintf(ctx->pool, "%d", random_mf ? 1 : 0);
        argv[6] = url;
        argv[7] = factors_string;
        argv[8] = NULL;
    }

    /* Make the call. */
    output = wai_buffer_new(ctx->pool);
    s = remctl_generic(ctx, argv, output);
    if (s != WA_ERR_NONE)
        return s;
    if (c->json)
        free((char *) argv[2]);

    /* Parse the XML or JSON results. */
    if (c->json) {
#ifdef HAVE_JANSSON
        s = json_parse_document(ctx, output, &json);
        if (s != WA_ERR_NONE)
            return s;
        s = json_parse_user_info(ctx, json, info);
        json_decref(json);
        return s;
#else /* !HAVE_JANSSON */
        s = WA_ERR_UNIMPLEMENTED;
        return wai_error_set(ctx, s, "not built with JSON support");
#endif
    } else {
        apr_xml_doc *doc = NULL;

        s = xml_parse_document(ctx, output, &doc);
        if (s != WA_ERR_NONE)
            return s;
        return xml_parse_user_info(ctx, doc, info);
    }

fail:
    if (json != NULL)
        json_decref(json);
    return wai_error_set(ctx, WA_ERR_NO_MEM, "cannot build JSON call");
}


/*
 * Call the user validation service via remctl and parse the results into a
 * webauth_user_validate struct.
 */
static int
remctl_validate(struct webauth_context *ctx, const char *user, const char *ip,
                const char *code, const char *type, const char *state,
                struct webauth_user_validate **validate)
{
    int s;
    const char *argv[8];
    struct wai_buffer *output;
    struct webauth_user_config *c = ctx->user;
#ifdef HAVE_JANSSON
    json_t *json = NULL;
#endif

    /*
     * Build the command.
     *
     * FIXME: The JSON code here is horrible and needs some better structure.
     * It will also leak memory if there is some failure adding the temporary
     * objects since those objects aren't decref'd.
     */
    argv[0] = c->command;
    argv[1] = "webkdc-validate";
    if (c->json) {
#ifdef HAVE_JANSSON
        json_t *factor, *value;

        json = json_object();
        if (json == NULL)
            goto fail;
        value = json_string(user);
        if (value == NULL)
            goto fail;
        if (json_object_set_new(json, "username", value) < 0)
            goto fail;
        if (ip != NULL) {
            value = json_string(ip);
            if (value == NULL)
                goto fail;
            if (json_object_set_new(json, "ip", value) < 0)
                goto fail;
        }
        if (state != NULL) {
            value = json_string(state);
            if (value == NULL)
                goto fail;
            if (json_object_set_new(json, "login_state", value) < 0)
                goto fail;
        }
        factor = json_object();
        if (factor == NULL)
            goto fail;
        if (type != NULL) {
            value = json_string(type);
            if (value == NULL)
                goto fail;
            if (json_object_set_new(factor, "capability", value) < 0)
                goto fail;
        }
        if (code != NULL) {
            value = json_string(code);
            if (value == NULL)
                goto fail;
            if (json_object_set_new(factor, "passcode", value) < 0)
                goto fail;
        }
        if (json_object_set_new(json, "factor", factor) < 0)
            goto fail;
        argv[2] = json_dumps(json, 0);
        if (argv[2] == NULL)
            goto fail;
        argv[3] = NULL;
        json_decref(json);
#else /* !HAVE_JANSSON */
        s = WA_ERR_UNIMPLEMENTED;
        return wai_error_set(ctx, s, "not built with JSON support");
#endif
    } else {
        argv[2] = user;
        argv[3] = ip;
        argv[4] = code;
        argv[5] = type;
        argv[6] = state;
        argv[7] = NULL;
    }
    output = wai_buffer_new(ctx->pool);
    s = remctl_generic(ctx, argv, output);
    if (s != WA_ERR_NONE)
        return s;
    if (c->json)
        free((char *) argv[2]);

    /* Parse the XML or JSON results. */
    if (c->json) {
#ifdef HAVE_JANSSON
        s = json_parse_document(ctx, output, &json);
        if (s != WA_ERR_NONE)
            return s;
        s = json_parse_user_validate(ctx, json, validate);
        json_decref(json);
        return s;
#else /* !HAVE_JANSSON */
        s = WA_ERR_UNIMPLEMENTED;
        return wai_error_set(ctx, s, "not built with JSON support");
#endif
    } else {
        apr_xml_doc *doc = NULL;

        s = xml_parse_document(ctx, output, &doc);
        if (s != WA_ERR_NONE)
            return s;
        return xml_parse_user_validate(ctx, doc, validate);
    }

fail:
    if (json != NULL)
        json_decref(json);
    return wai_error_set(ctx, WA_ERR_NO_MEM, "cannot build JSON call");
}


/*
 * Common code to sanity-check the environment for a user information call.
 * On any error, sets the WebAuth error message and returns an error code.
 */
static int
check_config(struct webauth_context *ctx)
{
    int s;

    if (ctx->user == NULL) {
        s = WA_ERR_INVALID;
        wai_error_set(ctx, s, "user information service not configured");
        return s;
    }
    if (ctx->user->protocol == WA_PROTOCOL_REMCTL) {
        if (ctx->user->keytab == NULL) {
            wai_error_set(ctx, WA_ERR_INVALID,
                          "keytab must be configured for remctl protocol");
            return WA_ERR_INVALID;
        }
#ifndef HAVE_REMCTL
        s = WA_ERR_UNIMPLEMENTED;
        return wai_error_set(ctx, s, "not built with remctl support");
#endif
    }
#ifndef HAVE_JANSSON
    if (ctx->user->json) {
        s = WA_ERR_UNIMPLEMENTED;
        return wai_error_set(ctx, s, "not built with JSON support");
    }
#endif
    return WA_ERR_NONE;
}


/*
 * Obtain user information for a given user.  The IP address of the user (as a
 * string) is also provided, defaulting to 127.0.0.1.  The final flag
 * indicates whether a site requested random multifactor and asks the user
 * information service to calculate whether multifactor is forced based on
 * that random multifactor chance.
 *
 * On success, sets the info parameter to a new webauth_userinfo struct
 * allocated from pool memory, sets random multifactor if we were asked to
 * attempt it, and returns WA_ERR_NONE.  On failure, returns an error code and
 * sets the info parameter to NULL, unless ignore_failure is set.  If
 * ignore_failure was set and the failure was due to failure to contact the
 * remote service, it instead returns an empty information struct.
 */
int
webauth_user_info(struct webauth_context *ctx, const char *user,
                  const char *ip, int random_mf, const char *url,
                  const char *factors, struct webauth_user_info **info)
{
    int s;

    *info = NULL;
    s = check_config(ctx);
    if (s != WA_ERR_NONE)
        return s;
    if (ip == NULL)
        ip = "127.0.0.1";
    switch (ctx->user->protocol) {
    case WA_PROTOCOL_REMCTL:
        s = remctl_info(ctx, user, ip, random_mf, url, factors, info);
        break;
    case WA_PROTOCOL_NONE:
    default:
        /* This should be impossible due to webauth_user_config checks. */
        wai_error_set(ctx, WA_ERR_INVALID, "invalid user info protocol");
        return WA_ERR_INVALID;
    }

    /*
     * If the call succeeded and random_multifactor was set, say that the
     * random multifactor check passed.  If the call failed but we were told
     * to ignore failures, create a fake return struct.
     */
    if (s == WA_ERR_NONE && random_mf)
        (*info)->random_multifactor = true;
    else if (s == WA_ERR_REMOTE_FAILURE && ctx->user->ignore_failure) {
        wai_log_error(ctx, WA_LOG_WARN, s, "user information service failure");
        s = WA_ERR_NONE;
        *info = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_info));
    }
    return s;
}


/*
 * Validate an authentication code for a given user (generally an OTP code).
 *
 * webauth_user_config must be called before this function.  Depending on the
 * method used, authentication credentials may also need to be set up before
 * calling this function.
 *
 * On success, sets the info parameter to a new webauth_user_info struct
 * allocated from pool memory and returns WA_ERR_NONE.  On failure, returns an
 * error code and sets the info parameter to NULL.  Note that success only
 * means that the call completed, not that the validation was successful.
 */
int
webauth_user_validate(struct webauth_context *ctx, const char *user,
                      const char *ip, const char *code, const char *type,
                      const char *state,
                      struct webauth_user_validate **result)
{
    int s;

    *result = NULL;
    s = check_config(ctx);
    if (s != WA_ERR_NONE)
        return s;
    if (ip == NULL)
        ip = "127.0.0.1";
    switch (ctx->user->protocol) {
    case WA_PROTOCOL_REMCTL:
        return remctl_validate(ctx, user, ip, code, type, state, result);
    case WA_PROTOCOL_NONE:
    default:
        /* This should be impossible due to webauth_user_config checks. */
        wai_error_set(ctx, WA_ERR_INVALID, "invalid user info protocol");
        return WA_ERR_INVALID;
    }
}
