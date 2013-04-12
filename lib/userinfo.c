/*
 * WebKDC interface to retrieving user information.
 *
 * These interfaces are used by the WebKDC implementation to retrieve data
 * about a user from the user information service.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011, 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <apr_xml.h>
#include <errno.h>
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
    int status = WA_ERR_NONE;;

    /* Verify that the new configuration is sane. */
    if (user->protocol != WA_PROTOCOL_REMCTL) {
        status = WA_ERR_UNIMPLEMENTED;
        wai_error_set(ctx, status, "unknown protocol %d", user->protocol);
        goto done;
    }
    if (user->host == NULL) {
        status = WA_ERR_INVALID;
        wai_error_set(ctx, status, "user information host must be set");
        goto done;
    }
    if (user->protocol == WA_PROTOCOL_REMCTL && user->keytab == NULL) {
        status = WA_ERR_INVALID;
        wai_error_set(ctx, status,
                      "keytab must be configured for remctl protocol");
        goto done;
    }

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
        wai_error_set(ctx, status, "invalid number %s in XML", string);
        return status;
    }
    return WA_ERR_NONE;
}


/*
 * Parse the factors or persistent-factors sections of a userinfo XML
 * document.  Stores the results in the provided factors APR array.  If
 * expiration is non-NULL, accept and parse a user expiration time into that
 * time_t pointer.  If valid_threshold is non-NULL, accept and parse a cutoff
 * time into that time_t pointer.  Returns a status code.
 */
static int UNUSED
parse_factors(struct webauth_context *ctx, apr_xml_elem *root,
              const apr_array_header_t **result, time_t *expiration,
              time_t *valid_threshold)
{
    apr_xml_elem *child;
    apr_array_header_t *factors = NULL;
    const char **type, *content;
    unsigned long value;
    int status;

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
            status = wai_xml_content(ctx, child, type);
            if (status != WA_ERR_NONE)
                return status;
        } else if (strcmp(child->name, "expiration") == 0) {
            if (expiration == NULL)
                continue;
            status = wai_xml_content(ctx, child, &content);
            if (status == WA_ERR_NONE) {
                status = convert_number(ctx, content, &value);
                *expiration = value;
            }
            if (status != WA_ERR_NONE)
                return status;
        } else if (strcmp(child->name, "valid-threshold") == 0) {
            if (valid_threshold == NULL)
                continue;
            status = wai_xml_content(ctx, child, &content);
            if (status == WA_ERR_NONE) {
                status = convert_number(ctx, content, &value);
                *valid_threshold = value;
            }
            if (status != WA_ERR_NONE)
                return status;
        }
    }

    /* Save the factors if we found any and the caller wants them. */
    if (factors != NULL && result != NULL)
        *result = factors;

    /* FIXME: Warn if expiration != NULL but no expiration was found. */
    return WA_ERR_NONE;
}


/*
 * Parse the login history section of a userinfo XML document.  Stores the
 * results in the provided webauth_user_info struct.  Returns a status code.
 */
static int UNUSED
parse_history(struct webauth_context *ctx, apr_xml_elem *root,
              const apr_array_header_t **result)
{
    apr_xml_elem *child;
    apr_xml_attr *attr;
    apr_array_header_t *logins = NULL;
    struct webauth_login *login;
    int status;
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
        status = wai_xml_content(ctx, child, &login->ip);
        if (status != WA_ERR_NONE)
            return status;
        for (attr = child->attr; attr != NULL; attr = attr->next)
            if (strcmp(attr->name, "name") == 0)
                login->hostname = attr->value;
            else if (strcmp(attr->name, "timestamp") == 0) {
                status = convert_number(ctx, attr->value, &timestamp);
                if (status != WA_ERR_NONE)
                    return status;
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
parse_user_info(struct webauth_context *ctx, apr_xml_doc *doc,
                struct webauth_user_info **result)
{
    apr_xml_elem *child;
    int s = WA_ERR_REMOTE_FAILURE;
    struct webauth_user_info *info;
    unsigned long value;
    const char *content;
    bool multifactor_required = false;

    /* We currently don't check that the user parameter is correct. */
    if (strcmp(doc->root->name, "authdata") != 0) {
        wai_error_set(ctx, s, "root element is %s, not authdata",
                      doc->root->name);
        return s;
    }

    /* Parse the XML. */
    info = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_info));
    for (child = doc->root->first_child; child != NULL; child = child->next) {
        s = WA_ERR_NONE;
        if (strcmp(child->name, "error") == 0)
            s = wai_xml_content(ctx, child, &info->error);
        else if (strcmp(child->name, "factors") == 0)
            s = parse_factors(ctx, child, &info->factors, NULL, NULL);
        else if (strcmp(child->name, "additional-factors") == 0)
            s = parse_factors(ctx, child, &info->additional, NULL, NULL);
        else if (strcmp(child->name, "multifactor-required") == 0)
            multifactor_required = true;
        else if (strcmp(child->name, "required-factors") == 0)
            s = parse_factors(ctx, child, &info->required, NULL, NULL);
        else if (strcmp(child->name, "persistent-factors") == 0)
            s = parse_factors(ctx, child, NULL, NULL, &info->valid_threshold);
        else if (strcmp(child->name, "login-history") == 0)
            s = parse_history(ctx, child, &info->logins);
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
    if (info->required == NULL && multifactor_required) {
        apr_array_header_t *required;

        required = apr_array_make(ctx->pool, 1, sizeof(const char *));
        APR_ARRAY_PUSH(required, const char *) = WA_FA_MULTIFACTOR;
        info->required = required;
    }

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
parse_user_validate(struct webauth_context *ctx, apr_xml_doc *doc,
                    struct webauth_user_validate **result)
{
    apr_xml_elem *child;
    int status = WA_ERR_REMOTE_FAILURE;
    struct webauth_user_validate *validate;
    const char *content;

    if (strcmp(doc->root->name, "authdata") != 0) {
        wai_error_set(ctx, status, "root element is %s, not authdata",
                      doc->root->name);
        return status;
    }
    validate = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_validate));
    for (child = doc->root->first_child; child != NULL; child = child->next) {
        if (strcmp(child->name, "success") == 0) {
            status = wai_xml_content(ctx, child, &content);
            if (status == WA_ERR_NONE)
                validate->success = (strcmp(content, "yes") == 0);
        } else if (strcmp(child->name, "factors") == 0)
            status = parse_factors(ctx, child, &validate->factors,
                                   &validate->factors_expiration, NULL);
        else if (strcmp(child->name, "persistent-factors") == 0)
            status = parse_factors(ctx, child, &validate->persistent,
                                   &validate->persistent_expiration,
                                   &validate->valid_threshold);
        else if (strcmp(child->name, "loa") == 0) {
            status = wai_xml_content(ctx, child, &content);
            if (status == WA_ERR_NONE)
                status = convert_number(ctx, content, &validate->loa);
        } else if (strcmp(child->name, "user-message") == 0)
            status = wai_xml_content(ctx, child, &validate->user_message);
        else if (strcmp(child->name, "login-state") == 0)
            status = wai_xml_content(ctx, child, &validate->login_state);
        if (status != WA_ERR_NONE)
            return status;
    }
    *result = validate;
    return WA_ERR_NONE;
}


/*
 * Issue a remctl command to the user information service.  Takes the
 * argv-style vector of the command to execute and a timeout (which may be 0
 * to use no timeout), and stores the resulting XML document in the provided
 * argument.  On any error, including remote failure to execute the command,
 * sets the WebAuth error and returns a status code.
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
    struct webauth_krb5 *kc = NULL;
    char *cache;
    int status;

    /* Initialize the remctl context. */
    r = remctl_new();
    if (r == NULL) {
        status = WA_ERR_NO_MEM;
        wai_error_set_system(ctx, status, errno, "initializing remctl");
        return status;
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
    status = webauth_krb5_new(ctx, &kc);
    if (status != WA_ERR_NONE)
        goto fail;
    status = webauth_krb5_init_via_keytab(ctx, kc, c->keytab, c->principal,
                                          NULL);
    if (status != WA_ERR_NONE)
        goto fail;
    status = webauth_krb5_get_cache(ctx, kc, &cache);
    if (status != WA_ERR_NONE)
        goto fail;
    if (!remctl_set_ccache(r, cache)) {
        if (setenv("KRB5CCNAME", cache, 1) < 0) {
            status = WA_ERR_NO_MEM;
            wai_error_set_system(ctx, status, errno,
                                 "setting KRB5CCNAME for remctl");
            goto fail;
        }
    }

    /* Set a timeout if one was given. */
    if (c->timeout > 0)
        remctl_set_timeout(r, c->timeout);

    /* Set up and execute the command. */
    if (c->command == NULL) {
        status = WA_ERR_INVALID;
        wai_error_set(ctx, status, "no remctl command specified");
        goto fail;
    }
    if (!remctl_open(r, c->host, c->port, c->identity)) {
        status = WA_ERR_REMOTE_FAILURE;
        wai_error_set(ctx, status, "%s", remctl_error(r));
        goto fail;
    }
    if (!remctl_command(r, command)) {
        status = WA_ERR_REMOTE_FAILURE;
        wai_error_set(ctx, status, "%s", remctl_error(r));
        goto fail;
    }

    /*
     * Retrieve the results.  Accumulate errors in the errors variable,
     * although we ignore that stream unless the exit status is non-zero.
     */
    parser = apr_xml_parser_create(ctx->pool);
    errors = wai_buffer_new(ctx->pool);
    do {
        out = remctl_output(r);
        if (out == NULL) {
            status = WA_ERR_REMOTE_FAILURE;
            wai_error_set(ctx, status, "%s", remctl_error(r));
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
                    wai_error_set(ctx, status, "XML error: %s", errbuf);
                    goto fail;
                }
                break;
            default:
                wai_buffer_append(errors, out->data, out->length);
                break;
            }
            break;
        case REMCTL_OUT_ERROR:
            status = WA_ERR_REMOTE_FAILURE;
            wai_error_set(ctx, status, "%s", errors->data);
            goto fail;
        case REMCTL_OUT_STATUS:
            if (out->status != 0) {
                if (wai_buffer_find_string(errors, "\n", 0, &offset))
                    errors->data[offset] = '\0';
                status = WA_ERR_REMOTE_FAILURE;
                wai_error_set(ctx, status, "%s", errors->data);
                goto fail;
            }
        case REMCTL_OUT_DONE:
        default:
            break;
        }
    } while (out->type == REMCTL_OUT_OUTPUT);
    remctl_close(r);
    r = NULL;

    /*
     * We have an accumulated XML document in the parser and don't think we've
     * seen any errors.  Finish the parsing and then hand off to document
     * analysis.
     */
    status = apr_xml_parser_done(parser, doc);
    if (status != APR_SUCCESS) {
        apr_xml_parser_geterror(parser, errbuf, sizeof(errbuf));
        wai_error_set(ctx, WA_ERR_REMOTE_FAILURE, "XML error: %s", errbuf);
        return WA_ERR_REMOTE_FAILURE;
    }

fail:
    if (parser != NULL)
        apr_xml_parser_done(parser, NULL);
    if (r != NULL)
        remctl_close(r);
    return status;
}
#else /* !HAVE_REMCTL */
static int
remctl_generic(struct webauth_context *ctx, const char **command UNUSED,
               apr_xml_doc **doc UNUSED)
{
    int status;

    status = WA_ERR_UNIMPLEMENTED;
    wai_error_set(ctx, status, "not built with remctl support");
    return status;
}
#endif /* !HAVE_REMCTL */


/*
 * Call the user information service via remctl and parse the results into a
 * webauth_user_info struct.
 */
static int
remctl_info(struct webauth_context *ctx, const char *user, const char *ip,
            int random_mf, const char *url, const char *factors,
            struct webauth_user_info **info)
{
    int status;
    const char *argv[9];
    apr_xml_doc *doc;
    struct webauth_user_config *c = ctx->user;

    /* A URL is required if we have factors. */
    if (url == NULL && factors != NULL)
        url = "";

    /* Build the command. */
    argv[0] = c->command;
    argv[1] = "webkdc-userinfo";
    argv[2] = user;
    argv[3] = ip;
    argv[4] = apr_psprintf(ctx->pool, "%lu", (unsigned long) time(NULL));
    argv[5] = apr_psprintf(ctx->pool, "%d", random_mf ? 1 : 0);
    argv[6] = url;
    argv[7] = factors;
    argv[8] = NULL;
    status = remctl_generic(ctx, argv, &doc);
    if (status != WA_ERR_NONE)
        return status;
    return parse_user_info(ctx, doc, info);
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
    int status;
    const char *argv[8];
    apr_xml_doc *doc;
    struct webauth_user_config *c = ctx->user;

    argv[0] = c->command;
    argv[1] = "webkdc-validate";
    argv[2] = user;
    argv[3] = ip;
    argv[4] = code;
    argv[5] = type;
    argv[6] = state;
    argv[7] = NULL;
    status = remctl_generic(ctx, argv, &doc);
    if (status != WA_ERR_NONE)
        return status;
    return parse_user_validate(ctx, doc, validate);
}


/*
 * Common code to sanity-check the environment for a user information call.
 * On any error, sets the WebAuth error message and returns an error code.
 */
static int
check_config(struct webauth_context *ctx)
{
    int status;

    if (ctx->user == NULL) {
        status = WA_ERR_INVALID;
        wai_error_set(ctx, status, "user information service not configured");
        return status;
    }
    if (ctx->user->protocol == WA_PROTOCOL_REMCTL) {
        if (ctx->user->keytab == NULL) {
            wai_error_set(ctx, WA_ERR_INVALID,
                          "keytab must be configured for remctl protocol");
            return WA_ERR_INVALID;
        }
#ifndef HAVE_REMCTL
        status = WA_ERR_UNIMPLEMENTED;
        wai_error_set(ctx, status, "not built with remctl support");
        return status;
#endif
    }
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
    int status;

    *info = NULL;
    status = check_config(ctx);
    if (status != WA_ERR_NONE)
        return status;
    if (ip == NULL)
        ip = "127.0.0.1";
    switch (ctx->user->protocol) {
    case WA_PROTOCOL_REMCTL:
        status = remctl_info(ctx, user, ip, random_mf, url, factors, info);
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
    if (status == WA_ERR_NONE && random_mf)
        (*info)->random_multifactor = true;
    else if (status == WA_ERR_REMOTE_FAILURE && ctx->user->ignore_failure) {
        wai_log_error(ctx, WA_LOG_WARN, status);
        status = WA_ERR_NONE;
        *info = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_info));
    }
    return status;
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
    int status;

    *result = NULL;
    status = check_config(ctx);
    if (status != WA_ERR_NONE)
        return status;
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
