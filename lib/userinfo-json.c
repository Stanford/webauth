/*
 * Command handling for the JSON user information service interface.
 *
 * The user information service calls support using either XML (the older
 * protocol) or JSON (the preferred protocol).  This file contains all of the
 * command creation and parsing logic for making JSON calls.
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

#include <limits.h>
#ifdef HAVE_JANSSON
# include <jansson.h>
#endif
#include <time.h>

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/factors.h>
#include <webauth/webkdc.h>

/*
 * Parsing macros that include error checking.  Each of these macros assume
 * that the s variable is available for a status and that the correct thing to
 * do on any failure is to return the status while taking no further action.
 */
#define PARSE_FACTORS(ctx, json, key, result, exp)                      \
    do {                                                                \
        s = json_parse_factors((ctx), (json), (key), (result), (exp));  \
        if (s != WA_ERR_NONE)                                           \
            return s;                                                   \
    } while (0)
#define PARSE_HISTORY(ctx, json, key, result)                   \
    do {                                                        \
        s = json_parse_history((ctx), (json), (key), (result)); \
        if (s != WA_ERR_NONE)                                   \
            return s;                                           \
    } while (0)
#define PARSE_INTEGER(ctx, json, key, result)                   \
    do {                                                        \
        unsigned long tmp;                                      \
        s = json_parse_integer((ctx), (json), (key), &tmp);     \
        if (s != WA_ERR_NONE)                                   \
            return s;                                           \
        *(result) = tmp;                                        \
    } while (0)
#define PARSE_STRING(ctx, json, key, result)                    \
    do {                                                        \
        s = json_parse_string((ctx), (json), (key), (result));  \
        if (s != WA_ERR_NONE)                                   \
            return s;                                           \
    } while (0)


/*
 * Stub out the calls to return an error if not built with JSON support.
 */
#ifndef HAVE_JANSSON

int
wai_user_info_json(struct webauth_context *ctx, const char *user UNUSED,
                   const char *ip UNUSED, int random_mf UNUSED,
                   const char *url UNUSED, const char *factors UNUSED,
                   struct webauth_user_info **info UNUSED)
{
    return wai_error_set(ctx, WA_ERR_UNIMPLEMENTED,
                         "not built with JSON support");
}

int
wai_user_validate_json(struct webauth_context *ctx, const char *user UNUSED,
                       const char *ip UNUSED, const char *code UNUSED,
                       const char *type UNUSED, const char *state UNUSED,
                       struct webauth_user_validate **validate UNUSED)
{
    return wai_error_set(ctx, WA_ERR_UNIMPLEMENTED,
                         "not built with JSON support");
}

#else /* HAVE_JANSSON */

/*
 * Given a WebAuth context, a JSON object, a key, and storage for an unsigned
 * long, retrieve the value of that key as an integer and store it in the
 * provided location.  If the key is not present or is null, set result to 0
 * and return success.  If the key is present but the value is not an integer
 * or is too long for an unsigned long, return an error code.
 */
static int
json_parse_integer(struct webauth_context *ctx, json_t *json, const char *key,
                   unsigned long *result)
{
    json_t *value;
    json_int_t integer;
    int s = WA_ERR_REMOTE_FAILURE;

    value = json_object_get(json, key);
    if (value == NULL || json_is_null(value)) {
        *result = 0;
        return WA_ERR_NONE;
    }
    if (!json_is_integer(value))
        return wai_error_set(ctx, s, "value of %s is not an integer", key);
    integer = json_integer_value(value);
    if (integer < 0 || integer > LONG_MAX)
        return wai_error_set(ctx, s, "value of %s (%" JSON_INTEGER_FORMAT
                             ") is out of range", key, integer);
    *result = integer;
    return WA_ERR_NONE;
}


/*
 * Given a WebAuth context, a JSON object, a key, and storage for an unsigned
 * long, retrieve the value of that key as a string and store a pool copy of
 * it in the provided location.  If the key is not present or is null, set
 * result to NULL and return success.  If the key is present but the value is
 * not an integer or is too long for an unsigned long, return an error code.
 */
static int
json_parse_string(struct webauth_context *ctx, json_t *json, const char *key,
                  const char **result)
{
    json_t *value;
    int s = WA_ERR_REMOTE_FAILURE;

    value = json_object_get(json, key);
    if (value == NULL || json_is_null(value)) {
        *result = NULL;
        return WA_ERR_NONE;
    }
    if (!json_is_string(value))
        return wai_error_set(ctx, s, "value of %s is not a string", key);
    *result = apr_pstrdup(ctx->pool, json_string_value(value));
    return WA_ERR_NONE;
}


/*
 * Parse factors from a JSON document, given an object and a key in that
 * object.  The factors may be present in two different forms: a simple list
 * of strings, or a list of objects with keys factor and expiration.  If
 * expiration information is present, and the expiration pointer is non-NULL,
 * the lowest expiration is stored in that pointer.  Returns a status code.
 */
static int
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
            PARSE_STRING(ctx, value, "factor", factor);
            PARSE_INTEGER(ctx, value, "expiration", &expires);
            if (expires > 0 && (expires < min_expires || min_expires == 0))
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


/*
 * Parse the logins section of a userinfo JSON document.  Stores the results
 * in the provided array.  Returns a status code.
 */
static int
json_parse_history(struct webauth_context *ctx, json_t *json, const char *key,
                   const apr_array_header_t **result)
{
    json_t *value, *array;
    apr_array_header_t *logins = NULL;
    struct webauth_login *login;
    int s;
    size_t size, i;

    /* Ensure the output variables are initialized in case of error. */
    if (result != NULL)
        *result = NULL;

    /* Get the array of factors. */
    array = json_object_get(json, key);
    if (array == NULL || json_is_null(array))
        return WA_ERR_NONE;
    if (!json_is_array(array)) {
        s = WA_ERR_REMOTE_FAILURE;
        return wai_error_set(ctx, s, "value of %s is not an array", key);
    }

    /* Walk the array looking for objects. */
    for (i = 0; i < json_array_size(array); i++) {
        value = json_array_get(array, i);
        if (!json_is_object(value)) {
            s = WA_ERR_REMOTE_FAILURE;
            return wai_error_set(ctx, s, "%s element is not object", key);
        }

        /* Create a new login entry, allocating the array if needed. */
        if (logins == NULL) {
            size = sizeof(struct webauth_login);
            logins = apr_array_make(ctx->pool, 5, size);
        }
        login = apr_array_push(logins);
        memset(login, 0, sizeof(*login));

        /* Parse the login information. */
        PARSE_STRING(ctx, value, "ip", &login->ip);
        if (login->ip == NULL) {
            s = WA_ERR_REMOTE_FAILURE;
            return wai_error_set(ctx, s, "%s element has no ip key", key);
        }
        PARSE_INTEGER(ctx, value, "timestamp", &login->timestamp);
        PARSE_STRING(ctx, value, "hostname", &login->hostname);
    }

    /* Return the results. */
    *result = logins;
    return WA_ERR_NONE;
}


/*
 * Given JSON returned by the webkdc-userinfo call, finish parsing it into a
 * newly-allocated webauth_user_info struct.  This function and all of the
 * functions it calls intentionally ignores unknown JSON attributes.  Returns
 * a status code.
 */
static int
json_parse_user_info(struct webauth_context *ctx, json_t *json,
                     struct webauth_user_info **result)
{
    const char *message, *detail;
    unsigned long code;
    json_t *value, *object;
    int s;
    struct webauth_user_info *info;

    /* Check for the success key. */
    value = json_object_get(json, "success");
    if (value == NULL) {
        s = WA_ERR_REMOTE_FAILURE;
        return wai_error_set(ctx, s, "no success key in JSON");
    }

    /* Create the data structure for the reply and pull out login_state. */
    info = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_info));
    PARSE_STRING(ctx, json, "login_state", &info->login_state);

    /*
     * If validation failed, return the message_detail string as the user
     * message if it is set.  If it is not set, report an internal error using
     * the message and the code.
     */
    if (json_is_false(value)) {
        PARSE_INTEGER(ctx, json, "code", &code);
        PARSE_STRING( ctx, json, "message", &message);
        PARSE_STRING( ctx, json, "message_detail", &detail);
        if (detail == NULL) {
            s = WA_ERR_REMOTE_FAILURE;
            return wai_error_set(ctx, s, "%s [%lu]", message, code);
        } else {
            wai_log_notice(ctx, "userinfo: webkdc-userinfo failed: %s [%lu]",
                           message, code);
            info->error = detail;
            *result = info;
            return WA_ERR_NONE;
        }
    }

    /* Grab the result key, which contains the meat of the reply. */
    object = json_object_get(json, "response");
    if (object == NULL || !json_is_object(object)) {
        s = WA_ERR_REMOTE_FAILURE;
        return wai_error_set(ctx, s, "no or malformed response key in JSON");
    }

    /* User info succeeded.  Pull the data out of the JSON reply. */
    PARSE_INTEGER(ctx, object, "persistent_threshold", &info->valid_threshold);
    PARSE_INTEGER(ctx, object, "password_expires", &info->password_expires);
    PARSE_INTEGER(ctx, object, "max_level_of_assurance", &info->max_loa);
    PARSE_STRING( ctx, object, "message", &info->user_message);
    PARSE_FACTORS(ctx, object, "available_factors", &info->factors, NULL);
    PARSE_FACTORS(ctx, object, "additional_factors", &info->additional, NULL);
    PARSE_FACTORS(ctx, object, "required_factors", &info->required, NULL);
    PARSE_HISTORY(ctx, object, "logins", &info->logins);

    /* Return the results. */
    *result = info;
    return WA_ERR_NONE;
}


/*
 * Given JSON returned by the webkdc-validate call, finish parsing it into a
 * newly-allocated webauth_user_validate struct.  This function and all of the
 * functions it calls intentionally ignores unknown JSON attributes.  Returns
 * a status code.
 */
static int
json_parse_user_validate(struct webauth_context *ctx, json_t *json,
                         struct webauth_user_validate **result)
{
    const char *message, *detail;
    unsigned long code;
    json_t *value, *object;
    int s;
    struct webauth_user_validate *validate;

    /* Check for the success key. */
    value = json_object_get(json, "success");
    if (value == NULL) {
        s = WA_ERR_REMOTE_FAILURE;
        return wai_error_set(ctx, s, "no success key in JSON");
    }

    /* Create the data structure for the reply. */
    validate = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_validate));
    PARSE_STRING(ctx, json, "login_state", &validate->login_state);

    /*
     * If validation failed, return the message_detail string as the user
     * message if it is set.  If it is not set, report an internal error using
     * the message and the code.
     */
    if (json_is_false(value)) {
        PARSE_INTEGER(ctx, json, "code", &code);
        PARSE_STRING( ctx, json, "message", &message);
        PARSE_STRING( ctx, json, "message_detail", &detail);
        if (detail == NULL) {
            s = WA_ERR_REMOTE_FAILURE;
            return wai_error_set(ctx, s, "%s [%lu]", message, code);
        } else {
            wai_log_notice(ctx, "userinfo: webkdc-validate failed: %s [%lu]",
                           message, code);
            validate->user_message = detail;
            *result = validate;
            return WA_ERR_NONE;
        }
    }
    validate->success = true;

    /* Grab the result key, which contains the meat of the reply. */
    object = json_object_get(json, "response");
    if (object == NULL || !json_is_object(object)) {
        s = WA_ERR_REMOTE_FAILURE;
        return wai_error_set(ctx, s, "no or malformed response key in JSON");
    }

    /* Validation succeeded.  Pull the data out of the JSON reply. */
    PARSE_INTEGER(ctx, object, "persistent_threshold",
                  &validate->valid_threshold);
    PARSE_INTEGER(ctx, object, "level_of_assurance", &validate->loa);
    PARSE_STRING( ctx, object, "message", &validate->user_message);
    PARSE_FACTORS(ctx, object, "factors", &validate->factors,
                  &validate->factors_expiration);
    PARSE_FACTORS(ctx, object, "persistent_factors", &validate->persistent,
                  &validate->persistent_expiration);

    /* Return the results. */
    *result = validate;
    return WA_ERR_NONE;
}


/*
 * Given an JSON document in a struct wai_buffer, parse it into a json_t
 * structure and store it in the provided argument.  The contents of the
 * buffer must be nul-terminated.  The caller is responsible for decrementing
 * the reference count on the json_t object when finished with it.
 *
 * If the parse fails, set the WebAuth error and return a status code.
 */
static int
json_parse_document(struct webauth_context *ctx, struct wai_buffer *string,
                    json_t **json)
{
    json_error_t error;

    *json = json_loads(string->data, 0, &error);
    if (*json == NULL)
        return wai_error_set(ctx, WA_ERR_REMOTE_FAILURE,
                             "JSON parse error: %s at byte %lu in %s",
                             error.text, (unsigned long) error.position,
                             string->data);
    return WA_ERR_NONE;
}


/*
 * Construct the arguments to a webkdc-userinfo command using the JSON
 * protocol.  Takes the user, ip, random flag, URL, and factor string, and
 * sets the command argument to point to a a NULL-terminated array of strings
 * suitable for passing to remctl_command.  Returns a status code.
 *
 * FIXME: The JSON code here is horrible and needs some better structure.  It
 * will also leak memory if there is some failure adding the temporary objects
 * since those objects aren't decref'd.
 */
static int
json_command_userinfo(struct webauth_context *ctx, const char *user,
                      const char *ip, int random_mf, const char *url,
                      const char *factors_string, const char ***command)
{
    const char **argv;
    const struct webauth_user_config *config = ctx->user;
    json_t *json = NULL;
    json_t *value, *member;
    char *arg;
    struct webauth_factors *factors;
    apr_array_header_t *factors_array;
    const char *factor;
    int i;

    *command = NULL;
    argv = apr_pcalloc(ctx->pool, 4 * sizeof(const char *));
    argv[0] = config->command;
    argv[1] = "webkdc-userinfo";
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
    arg = json_dumps(json, 0);
    if (arg == NULL)
        goto fail;
    argv[2] = apr_pstrdup(ctx->pool, arg);
    free(arg);
    argv[3] = NULL;
    json_decref(json);
    *command = argv;
    return WA_ERR_NONE;

fail:
    if (json != NULL)
        json_decref(json);
    return wai_error_set(ctx, WA_ERR_NO_MEM, "cannot build JSON call");
}


/*
 * Call the user information service via remctl and parse the results into a
 * webauth_user_info struct.
 */
int
wai_user_info_json(struct webauth_context *ctx, const char *user,
                   const char *ip, int random_mf, const char *url,
                   const char *factors, struct webauth_user_info **info)
{
    int s;
    struct wai_buffer *output;
    const char **argv;
    json_t *json = NULL;

    /* Build the command. */
    s = json_command_userinfo(ctx, user, ip, random_mf, url, factors, &argv);
    if (s != WA_ERR_NONE)
        return s;

    /* Make the call. */
    output = wai_buffer_new(ctx->pool);
    s = wai_user_remctl(ctx, argv, output);
    if (s != WA_ERR_NONE)
        return s;

    /* Parse the JSON results. */
    s = json_parse_document(ctx, output, &json);
    if (s != WA_ERR_NONE)
        return s;
    s = json_parse_user_info(ctx, json, info);
    json_decref(json);
    return s;
}


/*
 * Construct the arguments to a webkdc-validate command using the JSON
 * protocol.  Takes the user, ip, code, type, and state information and sets
 * the command argument to point to a a NULL-terminated array of strings
 * suitable for passing to remctl_command.  Returns a status code.
 *
 * FIXME: The JSON code here is horrible and needs some better structure.  It
 * will also leak memory if there is some failure adding the temporary objects
 * since those objects aren't decref'd.
 */
static int
json_command_validate(struct webauth_context *ctx, const char *user,
                      const char *ip, const char *code, const char *type,
                      const char *state, const char ***command)
{
    const char **argv;
    json_t *json = NULL;
    json_t *factor, *value;
    char *arg;
    const struct webauth_user_config *config = ctx->user;

    *command = NULL;
    argv = apr_pcalloc(ctx->pool, 4 * sizeof(const char *));
    argv[0] = config->command;
    argv[1] = "webkdc-validate";
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
    arg = json_dumps(json, 0);
    if (arg == NULL)
        goto fail;
    argv[2] = apr_pstrdup(ctx->pool, arg);
    free(arg);
    argv[3] = NULL;
    json_decref(json);
    *command = argv;
    return WA_ERR_NONE;

fail:
    if (json != NULL)
        json_decref(json);
    return wai_error_set(ctx, WA_ERR_NO_MEM, "cannot build JSON call");
}


/*
 * Call the user validation service via remctl and parse the results into a
 * webauth_user_validate struct.
 */
int
wai_user_validate_json(struct webauth_context *ctx, const char *user,
                       const char *ip, const char *code, const char *type,
                       const char *state,
                       struct webauth_user_validate **validate)
{
    int s;
    const char **argv = NULL;
    struct wai_buffer *output;
    json_t *json = NULL;

    /* Build the command. */
    s = json_command_validate(ctx, user, ip, code, type, state, &argv);
    if (s != WA_ERR_NONE)
        return s;
    output = wai_buffer_new(ctx->pool);
    s = wai_user_remctl(ctx, argv, output);
    if (s != WA_ERR_NONE)
        return s;

    /* Parse the JSON results. */
    s = json_parse_document(ctx, output, &json);
    if (s != WA_ERR_NONE)
        return s;
    s = json_parse_user_validate(ctx, json, validate);
    json_decref(json);
    return s;
}

#endif /* HAVE_JANSSON */
