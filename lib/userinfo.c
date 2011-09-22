/*
 * WebKDC interface to retrieving user metadata.
 *
 * These interfaces are used by the WebKDC implementation to retrieve metadata
 * about a user from the user metadata service.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_xml.h>
#include <errno.h>
#include <limits.h>
#include <remctl.h>
#include <time.h>

#include <lib/internal.h>
#include <webauth.h>
#include <webauth/basic.h>
#include <webauth/webkdc.h>
#include <util/macros.h>


/*
 * Configure how to access the user metadata service.  Takes the method, the
 * host, an optional port (may be 0 to use the default for that method), an
 * optional authentication identity for the remote service (may be NULL to use
 * the default for that method), and a method-specific command parameter such
 * as a remctl command name or a partial URL.  The configuration information
 * is stored in the WebAuth context and used for all subsequent
 * webauth_userinfo queries.
 */
int
webauth_user_config(struct webauth_context *ctx,
                    struct webauth_user_config *user)
{
    int status = WA_ERR_NONE;;

    if (user->protocol != WA_PROTOCOL_REMCTL) {
        status = WA_ERR_UNIMPLEMENTED;
        webauth_error_set(ctx, status, "unknown protocol %d", user->protocol);
        goto done;
    }
    if (user->host == NULL) {
        status = WA_ERR_INVALID;
        webauth_error_set(ctx, status, "user metadata host must be set");
        goto done;
    }
    if (user->protocol == WA_PROTOCOL_REMCTL && user->keytab == NULL) {
        status = WA_ERR_INVALID;
        webauth_error_set(ctx, status,
                          "keytab must be configured for remctl protocol");
        goto done;
    }
    ctx->user = apr_palloc(ctx->pool, sizeof(struct webauth_user_config));
    ctx->user->protocol = user->protocol;
    ctx->user->host = apr_pstrdup(ctx->pool, user->host);
    ctx->user->port = user->port;
    if (user->identity != NULL)
        ctx->user->identity = apr_pstrdup(ctx->pool, user->identity);
    else
        ctx->user->identity = NULL;
    if (user->command != NULL)
        ctx->user->command = apr_pstrdup(ctx->pool, user->command);
    else
        ctx->user->command = NULL;
    if (user->keytab != NULL)
        ctx->user->keytab = apr_pstrdup(ctx->pool, user->keytab);
    else
        ctx->user->keytab = NULL;
    if (user->principal != NULL)
        ctx->user->principal = apr_pstrdup(ctx->pool, user->principal);
    else
        ctx->user->principal = NULL;

done:
    return status;
}


/*
 * Convert a number in an XML document from a string to a number, storing it
 * in the provided variable.  Returns a status code.
 */
static int UNUSED
convert_number(struct webauth_context *ctx, const char *string,
               unsigned long *value)
{
    int status;
    char *end;

    errno = 0;
    *value = strtoul(string, &end, 10);
    if (*end != '\0' || (*value == ULONG_MAX && errno != 0)) {
        status = WA_ERR_REMOTE_FAILURE;
        webauth_error_set(ctx, status, "invalid number %s", string);
        return status;
    }
    return WA_ERR_NONE;
}


/*
 * Parse the factors section of a userinfo XML document.  Stores the results
 * in the provided webauth_user_info struct.  Returns a status code.
 */
static int UNUSED
parse_factors(struct webauth_context *ctx, apr_xml_elem *root,
              apr_array_header_t **factors)
{
    apr_xml_elem *child;
    const char **type;
    int status;

    for (child = root->first_child; child != NULL; child = child->next) {
        if (strcmp(child->name, "factor") == 0) {
            if (*factors == NULL)
                *factors = apr_array_make(ctx->pool, 2, sizeof(const char *));
            type = apr_array_push(*factors);
            status = webauth_xml_content(ctx, child, type);
            if (status != WA_ERR_NONE)
                return status;
        }
    }
    return WA_ERR_NONE;
}


/*
 * Parse the login history section of a userinfo XML document.  Stores the
 * results in the provided webauth_user_info struct.  Returns a status code.
 */
static int UNUSED
parse_history(struct webauth_context *ctx, apr_xml_elem *root,
              apr_array_header_t **logins)
{
    apr_xml_elem *child;
    apr_xml_attr *attr;
    struct webauth_login *login;
    int status;
    size_t size;
    unsigned long timestamp;

    for (child = root->first_child; child != NULL; child = child->next) {
        if (strcmp(child->name, "host") != 0)
            continue;
        if (*logins == NULL) {
            size = sizeof(struct webauth_login);
            *logins = apr_array_make(ctx->pool, 5, size);
        }
        login = apr_array_push(*logins);
        status = webauth_xml_content(ctx, child, &login->ip);
        if (status != WA_ERR_NONE)
            return status;
        for (attr = child->attr; attr != NULL; attr = attr->next)
            if (strcmp(attr->name, "name") == 0)
                login->hostname = attr->value;
            else if (strcmp(attr->name, "timestamp")) {
                status = convert_number(ctx, attr->value, &timestamp);
                if (status != WA_ERR_NONE)
                    return status;
                login->timestamp = timestamp;
            }
    }
    return WA_ERR_NONE;
}


/*
 * Given an XML document returned by the webkdc-userinfo call, however
 * obtained, finish parsing it into a newly-allocated webauth_user_info
 * struct.  This function and all of the functions it calls intentionally
 * ignores unknown XML elements or attributes.  Returns a status code.
 */
static int UNUSED
parse_user_info(struct webauth_context *ctx, apr_xml_doc *doc,
                struct webauth_user_info **result)
{
    apr_xml_elem *child;
    int status = WA_ERR_REMOTE_FAILURE;
    struct webauth_user_info *info;
    unsigned long value;
    const char *content;

    if (strcmp(doc->root->name, "authdata") != 0) {
        webauth_error_set(ctx, status, "root element is %s, not authdata",
                          doc->root->name);
        return status;
    }
    info = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_info));
    for (child = doc->root->first_child; child != NULL; child = child->next) {
        status = WA_ERR_NONE;
        if (strcmp(child->name, "factors") == 0)
            status = parse_factors(ctx, child, &info->factors);
        else if (strcmp(child->name, "multifactor-required") == 0)
            info->multifactor_required = true;
        else if (strcmp(child->name, "login-history") == 0)
            status = parse_history(ctx, child, &info->logins);
        else if (strcmp(child->name, "max-loa") == 0) {
            status = webauth_xml_content(ctx, child, &content);
            if (status == WA_ERR_NONE)
                status = convert_number(ctx, content, &info->max_loa);
        } else if (strcmp(child->name, "password-expires") == 0) {
            status = webauth_xml_content(ctx, child, &content);
            if (status == WA_ERR_NONE) {
                status = convert_number(ctx, content, &value);
                info->password_expires = value;
            }
        }
        if (status != WA_ERR_NONE)
            return status;
    }
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
parse_user_validate(struct webauth_context *ctx, apr_xml_doc *doc,
                    struct webauth_user_validate **result)
{
    apr_xml_elem *child;
    int status = WA_ERR_REMOTE_FAILURE;
    struct webauth_user_validate *validate;
    const char *content;

    if (strcmp(doc->root->name, "authdata") != 0) {
        webauth_error_set(ctx, status, "root element is %s, not authdata",
                          doc->root->name);
        return status;
    }
    validate = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_validate));
    for (child = doc->root->first_child; child != NULL; child = child->next) {
        if (strcmp(child->name, "success") == 0) {
            status = webauth_xml_content(ctx, child, &content);
            if (status == WA_ERR_NONE)
                validate->success = (strcmp(content, "yes") == 0);
        } else if (strcmp(child->name, "factors") == 0)
            status = parse_factors(ctx, child, &validate->factors);
        else if (strcmp(child->name, "loa") == 0) {
            status = webauth_xml_content(ctx, child, &content);
            if (status == WA_ERR_NONE)
                status = convert_number(ctx, content, &validate->loa);
        }
        if (status != WA_ERR_NONE)
            return status;
    }
    *result = validate;
    return WA_ERR_NONE;
}


/*
 * Issue a remctl command to the user metadata service.  Takes the argv-style
 * vector of the command to execute and stores the resulting XML document in
 * the provided argument.  On any error, including remote failure to execute
 * the command, sets the WebAuth error and returns a status code.
 */
#ifdef HAVE_REMCTL
static int
remctl_generic(struct webauth_context *ctx, const char **command,
               apr_xml_doc **doc)
{
    struct remctl *r = NULL;
    struct remctl_output *out;
    apr_xml_parser *parser = NULL;
    size_t offset;
    char errbuf[BUFSIZ] = "";
    struct buffer *errors;
    struct webauth_user_config *c = ctx->user;
    WEBAUTH_KRB5_CTXT *kctx = NULL;
    char *cache;
    int status;

    /*
     * Obtain authentication credentials from the configured keytab and
     * principal.
     *
     * FIXME: This changes global process state to point to the correct
     * Kerberos ticket cache.  Fix once remctl has a way of setting the
     * Kerberos ticket cache to use.
     *
     * FIXME: Leaks memory on every use.
     */
    status = webauth_krb5_new(&kctx);
    if (status != WA_ERR_NONE) {
        webauth_error_set(ctx, status, "initializing Kerberos context");
        return status;
    }
    status = webauth_krb5_init_via_keytab(kctx, c->keytab, c->principal, NULL);
    if (status != WA_ERR_NONE) {
        webauth_error_set(ctx, status, "%s", webauth_krb5_error_message(kctx));
        return status;
    }
    status = webauth_krb5_get_cache(kctx, &cache);
    if (cache == NULL) {
        if (status == WA_ERR_KRB5)
            webauth_error_set(ctx, status, "%s",
                              webauth_krb5_error_message(kctx));
        else
            webauth_error_set(ctx, status, "%s",
                              webauth_error_message(NULL, status));
        return status;
    }
    if (setenv("KRB5CCNAME", cache, 1) < 0) {
        status = WA_ERR_NO_MEM;
        webauth_error_set(ctx, status, "setting KRB5CCNAME");
        free(cache);
        return status;
    }
    free(cache);

    /* Set up and execute the command. */
    if (c->command == NULL) {
        webauth_error_set(ctx, WA_ERR_INVALID, "no remctl command specified");
        return WA_ERR_INVALID;
    }
    r = remctl_new();
    if (r == NULL) {
        webauth_error_set(ctx, WA_ERR_NO_MEM, "%s", strerror(errno));
        return WA_ERR_NO_MEM;
    }
    if (!remctl_open(r, c->host, c->port, c->identity)) {
        status = WA_ERR_REMOTE_FAILURE;
        webauth_error_set(ctx, status, "%s", remctl_error(r));
        goto fail;
    }
    if (!remctl_command(r, command)) {
        status = WA_ERR_REMOTE_FAILURE;
        webauth_error_set(ctx, status, "%s", remctl_error(r));
        goto fail;
    }

    /*
     * Retrieve the results.  Accumulate errors in the errors variable,
     * although we ignore that stream unless the exit status is non-zero.
     */
    parser = apr_xml_parser_create(ctx->pool);
    errors = webauth_buffer_new(ctx->pool);
    do {
        out = remctl_output(r);
        if (out == NULL) {
            status = WA_ERR_REMOTE_FAILURE;
            webauth_error_set(ctx, status, "%s", remctl_error(r));
            goto fail;
        }
        switch (out->type) {
        case REMCTL_OUT_OUTPUT:
            switch (out->stream) {
            case 1:
                status = apr_xml_parser_feed(parser, out->data, out->length);
                if (status != APR_SUCCESS) {
                    apr_xml_parser_geterror(parser, errbuf, sizeof(errbuf));
                    status = WA_ERR_REMOTE_FAILURE;
                    webauth_error_set(ctx, status, "XML error: %s", errbuf);
                    goto fail;
                }
                break;
            default:
                webauth_buffer_append(errors, out->data, out->length);
                break;
            }
            break;
        case REMCTL_OUT_ERROR:
            status = WA_ERR_REMOTE_FAILURE;
            webauth_error_set(ctx, status, "%s", errors->data);
            goto fail;
        case REMCTL_OUT_STATUS:
            if (out->status != 0) {
                if (webauth_buffer_find_string(errors, "\n", 0, &offset))
                    errors->data[offset] = '\0';
                status = WA_ERR_REMOTE_FAILURE;
                webauth_error_set(ctx, status, "%s", errors->data);
                goto fail;
            }
        case REMCTL_OUT_DONE:
        default:
            break;
        }
    } while (out->type == REMCTL_OUT_OUTPUT);
    remctl_close(r);
    r = NULL;
    webauth_krb5_free(kctx);
    kctx = NULL;

    /*
     * We have an accumulated XML document in the parser and don't think we've
     * seen any errors.  Finish the parsing and then hand off to document
     * analysis.
     */
    status = apr_xml_parser_done(parser, doc);
    if (status != APR_SUCCESS) {
        apr_xml_parser_geterror(parser, errbuf, sizeof(errbuf));
        webauth_error_set(ctx, WA_ERR_REMOTE_FAILURE, "XML error: %s", errbuf);
        return WA_ERR_REMOTE_FAILURE;
    }

fail:
    if (parser != NULL)
        apr_xml_parser_done(parser, NULL);
    if (r != NULL)
        remctl_close(r);
    if (kctx != NULL)
        webauth_krb5_free(kctx);
    return status;
}
#else /* !HAVE_REMCTL */
static int
remctl_generic(struct webauth_context *ctx, const char **command UNUSED,
               apr_xml_doc **doc UNUSED)
{
    int status;

    status = WA_ERR_UNIMPLEMENTED;
    webauth_error_set(ctx, status, "not built with remctl support");
    return status;
}
#endif /* !HAVE_REMCTL */


/*
 * Call the user metadata info service via remctl and parse the results into a
 * webauth_user_info struct.
 */
static int
remctl_info(struct webauth_context *ctx, const char *user, const char *ip,
            int random_multifactor, struct webauth_user_info **info)
{
    int status;
    const char *argv[7];
    apr_xml_doc *doc;
    struct webauth_user_config *c = ctx->user;

    argv[0] = c->command;
    argv[1] = "webkdc-userinfo";
    argv[2] = user;
    argv[3] = ip;
    argv[4] = apr_psprintf(ctx->pool, "%lu", (unsigned long) time(NULL));
    argv[5] = apr_psprintf(ctx->pool, "%d", random_multifactor ? 1 : 0);
    argv[6] = NULL;
    status = remctl_generic(ctx, argv, &doc);
    if (status != WA_ERR_NONE)
        return status;
    return parse_user_info(ctx, doc, info);
}


/*
 * Call the user metadata validation service via remctl and parse the results
 * into a webauth_user_validate struct.
 */
static int
remctl_validate(struct webauth_context *ctx, const char *user, const char *ip,
                const char *code, struct webauth_user_validate **validate)
{
    int status;
    const char *argv[6];
    apr_xml_doc *doc;
    struct webauth_user_config *c = ctx->user;

    argv[0] = c->command;
    argv[1] = "webkdc-validate";
    argv[2] = user;
    argv[3] = ip;
    argv[4] = code;
    argv[5] = NULL;
    status = remctl_generic(ctx, argv, &doc);
    if (status != WA_ERR_NONE)
        return status;
    return parse_user_validate(ctx, doc, validate);
}


/*
 * Common code to sanity-check the environment for a user metadata call.  On
 * any error, sets the WebAuth error message and returns an error code.
 */
static int
check_config(struct webauth_context *ctx)
{
    int status;

    if (ctx->user == NULL) {
        status = WA_ERR_INVALID;
        webauth_error_set(ctx, status, "user metadata service not configured");
        return status;
    }
    if (ctx->user->protocol == WA_PROTOCOL_REMCTL) {
        if (ctx->user->keytab == NULL) {
            webauth_error_set(ctx, WA_ERR_INVALID,
                              "keytab must be configured for remctl protocol");
            return WA_ERR_INVALID;
        }
#ifndef HAVE_REMCTL
        status = WA_ERR_UNIMPLEMENTED;
        webauth_error_set(ctx, status, "not built with remctl support");
        return status;
#endif
    }
    return WA_ERR_NONE;
}


/*
 * Obtain user information for a given user.  The IP address of the user (as a
 * string) is also provided, defaulting to 127.0.0.1.  The final flag
 * indicates whether a site requested random multifactor and asks the user
 * metadata service to calculate whether multifactor is forced based on that
 * random multifactor chance.
 *
 * On success, sets the info parameter to a new webauth_userinfo struct
 * allocated from pool memory and returns WA_ERR_NONE.  On failure, returns an
 * error code and sets the info parameter to NULL.
 */
int
webauth_user_info(struct webauth_context *ctx, const char *user,
                  const char *ip, int random_multifactor,
                  struct webauth_user_info **info)
{
    int status;

    *info = NULL;
    status = check_config(ctx);
    if (status != WA_ERR_NONE)
        return status;
    if (ip == NULL)
        ip = "127.0.0.1";
    switch (ctx->user->protocol) {
    case WA_PROTOCOL_REMCTL:
        return remctl_info(ctx, user, ip, random_multifactor, info);
    case WA_PROTOCOL_NONE:
    default:
        /* This should be impossible due to webauth_user_config checks. */
        webauth_error_set(ctx, WA_ERR_INVALID, "invalid protocol");
        return WA_ERR_INVALID;
    }
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
                      const char *ip, const char *code,
                      struct webauth_user_validate **result)
{
    int status;

    *result = NULL;
    status = check_config(ctx);
    if (status != WA_ERR_NONE)
        return status;
    if (ip == NULL)
        ip = "127.0.0.1";
    switch (ctx->user->protocol) {
    case WA_PROTOCOL_REMCTL:
        return remctl_validate(ctx, user, ip, code, result);
    case WA_PROTOCOL_NONE:
    default:
        /* This should be impossible due to webauth_user_config checks. */
        webauth_error_set(ctx, WA_ERR_INVALID, "invalid protocol");
        return WA_ERR_INVALID;
    }
}
