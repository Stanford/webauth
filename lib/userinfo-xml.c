/*
 * Command handling for the XML user information service interface.
 *
 * The user information service calls support using either XML (the older
 * protocol) or JSON (the preferred protocol).  This file contains all of the
 * command creation and parsing logic for making XML calls.
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
#include <limits.h>
#include <time.h>

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/factors.h>
#include <webauth/webkdc.h>


/*
 * Convert a number in an XML document from a string to a number, storing it
 * in the provided variable.  Returns a status code.
 */
static int
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
static int
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
static int
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
static int
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
static int
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
static int
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
 * Call the user information service using the XML protocol and parse the
 * results into a webauth_user_info struct.  Returns a status code.
 */
int
wai_user_info_xml(struct webauth_context *ctx, const char *user,
                  const char *ip, int random_mf, const char *url,
                  const char *factors_string, struct webauth_user_info **info)
{
    int s;
    struct wai_buffer *output;
    const char *argv[9];
    apr_xml_doc *doc = NULL;
    struct webauth_user_config *config = ctx->user;

    /* Build the command. */
    argv[0] = config->command;
    argv[1] = "webkdc-userinfo";
    argv[2] = user;
    argv[3] = (ip == NULL) ? "127.0.0.1" : ip;
    argv[4] = apr_psprintf(ctx->pool, "%lu", (unsigned long) time(NULL));
    argv[5] = random_mf ? "1" : "0";
    argv[6] = (url == NULL && factors_string != NULL) ? "" : url;
    argv[7] = factors_string;
    argv[8] = NULL;

    /* Make the call. */
    output = wai_buffer_new(ctx->pool);
    s = wai_user_remctl(ctx, argv, output);
    if (s != WA_ERR_NONE)
        return s;

    /* Parse the results. */
    s = xml_parse_document(ctx, output, &doc);
    if (s != WA_ERR_NONE)
        return s;
    return xml_parse_user_info(ctx, doc, info);
}


/*
 * Call the user validation service via remctl and parse the results into a
 * webauth_user_validate struct.
 */
int
wai_user_validate_xml(struct webauth_context *ctx, const char *user,
                      const char *ip, const char *code, const char *type,
                      const char *state,
                      struct webauth_user_validate **validate)
{
    int s;
    const char *argv[8];
    struct wai_buffer *output;
    apr_xml_doc *doc = NULL;
    struct webauth_user_config *config = ctx->user;

    /* Build the command. */
    argv[0] = config->command;
    argv[1] = "webkdc-validate";
    argv[2] = user;
    argv[3] = (ip == NULL) ? "127.0.0.1" : ip;
    argv[4] = code;
    argv[5] = type;
    argv[6] = state;
    argv[7] = NULL;
    output = wai_buffer_new(ctx->pool);
    s = wai_user_remctl(ctx, argv, output);
    if (s != WA_ERR_NONE)
        return s;

    /* Parse the XML results. */
    s = xml_parse_document(ctx, output, &doc);
    if (s != WA_ERR_NONE)
        return s;
    return xml_parse_user_validate(ctx, doc, validate);
}
