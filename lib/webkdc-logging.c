/*
 * Logging of WebKDC actions.
 *
 * Provides functions to log actions taken by the WebKDC.  Currently, this
 * only supports logging a <requestTokenRequest> from the WebLogin server.
 *
 * Originally written by Roland Schemers
 * Substantially updated by Russ Allbery <eagle@eyrie.org>
 * Copyright 2002, 2003, 2004, 2005, 2006, 2008, 2009, 2010, 2011, 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <apr_lib.h>
#include <assert.h>

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/factors.h>
#include <webauth/tokens.h>
#include <webauth/webkdc.h>


/*
 * Given a message, scan it for whitespace or double quotes.  If there are
 * any, enclose it in double quotes and escape any inner double quotes.
 */
static const char *
log_escape(apr_pool_t *pool, const char *message)
{
    size_t length = 0;
    size_t quotes = 0;
    bool escape = false;
    const char *p;
    char *q, *result;

    /* Convert NULL strings into the empty string for logging. */
    if (message == NULL)
        return "";

    /*
     * Scan the string for whitespace or double quotes.  Count double quotes,
     * since we're going to double each one.
     */
    for (p = message; *p != '\0'; p++) {
        length++;
        if (apr_isspace(*p))
            escape = true;
        else if (*p == '"') {
            escape = true;
            quotes++;
        }
    };

    /* If nothing special is going on, return the string verbatim. */
    if (!escape)
        return message;

    /*
     * Allocate room for the leading and trailing quotes plus an extra
     * character for each quote we're doubling.
     */
    result = apr_palloc(pool, length + quotes + 3);
    result[0] = '"';
    for (p = message, q = result + 1; *p != '\0'; p++, q++) {
        *q = *p;
        if (*p == '"')
            *q++ = '"';
    }
    *q++ = '"';
    *q++ = '\0';
    return result;
}


/*
 * Add a given key/value attribute to the log message (given as a buffer).
 * Escapes the value if necessary, and handles NULL values.
 */
static void
log_attribute(struct wai_buffer *message, const char *key, const char *value)
{
    const char *escaped;

    if (message->used != 0)
        wai_buffer_append(message, " ", 1);
    escaped = log_escape(message->pool, value);
    wai_buffer_append_sprintf(message, "%s=%s", key, escaped);
}


/*
 * Log the login request.  We do this once we determine whether the request
 * will be successful or not, as the last thing that we do before returning to
 * the caller.  This function constructs a general key/value pair log format.
 *
 * Takes the request, the response, the WebAuth status of the authentication
 * (after mapping to a protocol error), the list of login tokens (used to log
 * what login methods were used), and the request token.  Assumes that any
 * error message is the current webauth_error_message.
 */
void
wai_webkdc_log_login(struct webauth_context *ctx,
                     const struct wai_webkdc_login_state *state, int result,
                     const struct webauth_webkdc_login_response *response)
{
    struct wai_buffer *message;
    struct webauth_token_request *req;
    const struct webauth_token_webkdc_proxy *wpt;
    const char *subject, *login_type;
    const char *error = NULL;
    int i;

    /*
     * Get any WebAuth error message first thing in case any subsequent calls
     * set a WebAuth status.
     */
    if (result != WA_ERR_NONE)
        error = webauth_error_message(ctx, result);

    /* If we don't have a notice logging handler, avoid lots of work. */
    if (ctx->notice.callback == NULL)
        return;

    /* We're going to accumulate the log message in this buffer. */
    message = wai_buffer_new(ctx->pool);

    /* Add basic information from the request. */
    log_attribute(message, "event",    "requestToken");
    log_attribute(message, "from",     state->client_ip);
    log_attribute(message, "clientIp", state->remote_ip);
    log_attribute(message, "server",   response->requester);
    log_attribute(message, "url",      response->return_url);

    /* If we were unable to authenticate the user, log them as <unknown>. */
    subject = (response->subject == NULL) ? "<unknown>" : response->subject;
    log_attribute(message, "user", subject);

    /* Gather information about the login tokens. */
    login_type = NULL;
    if (!apr_is_empty_array(state->logins))
        for (i = 0; i < state->logins->nelts; i++) {
            const struct webauth_token *token;

            token = APR_ARRAY_IDX(state->logins, i, struct webauth_token *);
            assert(token->type == WA_TOKEN_LOGIN);
            if (token->token.login.password != NULL) {
                if (login_type == NULL)
                    login_type = "password";
                else if (strcmp(login_type, "otp") == 0)
                    login_type = "password,otp";
            } else if (token->token.login.otp != NULL) {
                if (login_type == NULL)
                    login_type = "otp";
                else if (strcmp(login_type, "password") == 0)
                    login_type = "password,otp";
            }
        }

    /* Log information about the request. */
    req = state->request;
    if (req != NULL) {
        log_attribute(message, "rtt", req->type);
        if (strcmp(req->type, "id") == 0)
            log_attribute(message, "sa", req->auth);
        else if (strcmp(req->type, "proxy") == 0)
            log_attribute(message, "pt", req->proxy_type);
        if (req->initial_factors != NULL)
            log_attribute(message, "wifactors", req->initial_factors);
        if (req->session_factors != NULL)
            log_attribute(message, "wsfactors", req->session_factors);
        if (req->loa > 0)
            wai_buffer_append_sprintf(message, " wloa=%lu", req->loa);
        if (req->options != NULL)
            log_attribute(message, "ro", req->options);
        if (login_type != NULL)
            log_attribute(message, "login", login_type);
    }

    /* Log information about the authentication. */
    if (response->authz_subject != NULL)
        log_attribute(message, "authz", response->authz_subject);
    if (state->wkproxy != NULL) {
        wpt = &state->wkproxy->token.webkdc_proxy;
        if (wpt->initial_factors != NULL)
            log_attribute(message, "ifactors", wpt->initial_factors);
        if (wpt->session_factors != NULL)
            log_attribute(message, "sfactors", wpt->session_factors);
        if (wpt->loa > 0)
            wai_buffer_append_sprintf(message, " loa=%lu", wpt->loa);
    }

    /* Finally, log the error code and error message. */
    wai_buffer_append_sprintf(message, " lec=%d", result);
    if (error != NULL)
        log_attribute(message, "lem", error);

    /* Actually log the message. */
    wai_log_notice(ctx, "%s", message->data);
}
