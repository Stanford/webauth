/*
 * Core Apache WebKDC module code.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2004, 2005, 2006, 2008, 2009, 2010, 2011, 2012, 2013,
 *     2014 The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config-mod.h>
#include <portable/apache.h>
#include <portable/apr.h>
#include <portable/stdbool.h>

#include <apr_base64.h>
#include <apr_lib.h>
#include <apr_xml.h>

#include <modules/webkdc/mod_webkdc.h>
#include <util/macros.h>
#include <webauth/basic.h>
#include <webauth/factors.h>
#include <webauth/keys.h>
#include <webauth/krb5.h>
#include <webauth/tokens.h>
#include <webauth/webkdc.h>

APLOG_USE_MODULE(webkdc);


/*
 * Called at any entry point where we may be doing WebKDC operations that need
 * a keyring.  Do lazy initialization of the in-memory keyring from the disk
 * file and store it in the virtual host context.  Returns true if the keyring
 * could be loaded correctly and false otherwise.
 */
static bool
ensure_keyring_loaded(MWK_REQ_CTXT *rc)
{
    int s;

    /* FIXME: Should use a per-virtual-host mutex instead of a global one. */
    mwk_lock_mutex(rc, MWK_MUTEX_KEYRING);
    if (rc->sconf->ring != NULL) {
        mwk_unlock_mutex(rc, MWK_MUTEX_KEYRING);
        return true;
    }
    s = mwk_cache_keyring(rc->r->server, rc->sconf);
    mwk_unlock_mutex(rc, MWK_MUTEX_KEYRING);
    return (s == WA_ERR_NONE && rc->sconf->ring != NULL);
}


/*
 * if msg has any whitespace or double quotes in it, enclose
 * it in double quotes, and escape any inner double quotes
 */
static const char *
log_escape(MWK_REQ_CTXT *rc, const char *msg)
{
    size_t len, space, quotes;
    const char *p;
    char *d, *q;

    len = 0;
    space = 0;
    quotes = 0;

    for (p = msg; *p; p++) {
        len++;
        if (apr_isspace(*p))
            space = 1;
        else if (*p == '"') {
            quotes = 1;
            len++;
        }
    }

    if (quotes == 0 && space == 0)
        return msg;

    d = q = apr_palloc(rc->r->pool, len + 3); /* two quotes + \0 */

    *d++ = '"';
    for (p=msg; *p; p++) {
        *d++ = *p;
        if (*p == '"')
            *d++ = '"';
    }
    *d++ = '"';
    *d++ = '\0';
    return q;
}

/*
 * generate <errorResponse> message from error stored in rc
 */
static int
generate_errorResponse(MWK_REQ_CTXT *rc)
{
    char ec_buff[32];

    if (rc->error_code==0) {
        rc->error_code = WA_PEC_SERVER_FAILURE;
    }

    sprintf(ec_buff,"%d", rc->error_code);

    if (rc->error_message == NULL) {
        rc->error_message ="<this shouldn't be happening!>";
    }

    ap_rvputs(rc->r,
              "<errorResponse><errorCode>",
              ec_buff,
              "</errorCode><errorMessage>",
              apr_xml_quote_string(rc->r->pool, rc->error_message, 0),
              "</errorMessage></errorResponse>",
              NULL);
    ap_rflush(rc->r);

    if (rc->need_to_log) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webkdc: %s: %s (%d)", rc->mwk_func,
                     rc->error_message, rc->error_code);
    }
    return OK;
}


/*
 * sets error info in "rc" which will bubble up to original caller.
 * also returns MWK_ERROR to allow it to be used as return value
 */
static enum mwk_status
set_errorResponse(MWK_REQ_CTXT *rc, int ec, const char *message,
                  const char *mwk_func, bool log)
{
    rc->error_code = ec;
    rc->error_message = message;
    rc->mwk_func = mwk_func;
    rc->need_to_log = log;
    return MWK_ERROR;
}


/*
 * log information about a bad element in XML and generate errorResponse
 */
static enum mwk_status
unknown_element(MWK_REQ_CTXT *rc,
                const char *mwk_func, const char *parent, const char *u)
{
    char *msg = apr_psprintf(rc->r->pool, "unknown element in <%s>: <%s>",
                             parent, u);
    return set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg, mwk_func, true);
}


/*
 * concat all the text pieces together and return data, or
 * NULL if an error occured.
 */
static char *
get_elem_text(MWK_REQ_CTXT *rc, apr_xml_elem *e, const char *mwk_func)
{
    MWK_STRING string;
    mwk_init_string(&string, rc->r->pool);

    if (e->first_cdata.first &&
        e->first_cdata.first->text) {
        apr_text *t;
         for (t = e->first_cdata.first; t != NULL; t = t->next) {
            mwk_append_string(&string, t->text, 0);
        }
    }

    if (!string.data || string.data[0] == '\0') {
        char *msg = apr_psprintf(rc->r->pool, "<%s> does not contain data",
                                 e->name);
        set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg, mwk_func, true);
        return NULL;
    }
    return string.data;
}

/*
 * get an attr from an element. if required and not found, we
 * log an error and generate an errorResponse.
 */
static const char *
get_attr_value(MWK_REQ_CTXT *rc,apr_xml_elem *e,
               const char *name, int required, const char *mwk_func)
{
    apr_xml_attr *a;

    for (a = e->attr; a != NULL; a = a->next) {
        if (strcmp(a->name, name) == 0) {
            return a->value;
        }
    }

    if (required) {
        char *msg = apr_psprintf(rc->r->pool, "can't find attr in <%s>: %s",
                                 e->name, name);
        set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg, mwk_func, true);
    }
    return NULL;
}


/*
 * find an element in the specified element. if required and not found, we
 * log an error and generate an errorResponse.
 */
static apr_xml_elem *
get_element(MWK_REQ_CTXT *rc,apr_xml_elem *e,
            const char *name, int required, const char *mwk_func)
{
    apr_xml_elem *child;

    for (child = e->first_child; child != NULL; child = child->next) {
        if (strcmp(child->name, name) == 0) {
            return child;
        }
    }

    if (required) {
        char *msg = apr_psprintf(rc->r->pool, "can't find element in <%s>: %s",
                                 e->name, name);
        set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg, mwk_func, true);
    }
    return NULL;
}

/*
 * search through subject credentials for a proxy-token of the requested
 * type.
 */
static struct webauth_token_webkdc_proxy *
find_proxy_token(MWK_REQ_CTXT *rc,
                 MWK_SUBJECT_CREDENTIAL *sub_cred,
                 const char *type,
                 const char *mwk_func,
                 bool set_error)
{
    size_t i;
    char *msg;

    if (strcmp(sub_cred->type, "proxy") == 0) {
        for (i = 0; i < sub_cred->u.proxy.num_proxy_tokens; i++) {
            if (strcmp(sub_cred->u.proxy.pt[i].proxy_type, type) == 0) {
                return &sub_cred->u.proxy.pt[i];
            }
        }
    }
    if (set_error) {
        msg = apr_psprintf(rc->r->pool,
                           "need a proxy-token of type: %s", type);
        set_errorResponse(rc, WA_PEC_PROXY_TOKEN_REQUIRED, msg, mwk_func,
                          true);
    }
    return NULL;
}

/*
 */
static enum mwk_status
parse_requesterCredential(MWK_REQ_CTXT *rc, apr_xml_elem *e,
                          MWK_REQUESTER_CREDENTIAL *req_cred,
                          const char **req_subject_out)
{
    int status;
    struct webauth_token *data;
    static const char*mwk_func = "parse_requesterCredential";
    const char *at = get_attr_value(rc, e, "type",  1, mwk_func);

    *req_subject_out = "<unknown>";

    if (at == NULL) {
        return MWK_ERROR;
    }

    req_cred->type = apr_pstrdup(rc->r->pool, at);

    if (strcmp(at, "service") == 0) {
        char *token = get_elem_text(rc, e, mwk_func);

        if (token == NULL)
            return MWK_ERROR;
        if (!ensure_keyring_loaded(rc))
            return set_errorResponse(rc, WA_PEC_SERVER_FAILURE, "no keyring",
                                     mwk_func, true);
        status = webauth_token_decode(rc->ctx, WA_TOKEN_WEBKDC_SERVICE, token,
                                      rc->sconf->ring, &data);
        if (status != WA_ERR_NONE) {
            mwk_log_webauth_error(rc->ctx, rc->r->server, status, mwk_func,
                                  "webauth_token_decode", NULL);
            if (status == WA_ERR_TOKEN_EXPIRED) {
                set_errorResponse(rc, WA_PEC_SERVICE_TOKEN_EXPIRED,
                                  "service token was expired",
                                  mwk_func, false);
            } else if (status == WA_ERR_BAD_HMAC) {
                set_errorResponse(rc, WA_PEC_SERVICE_TOKEN_INVALID,
                                  "can't decrypt service token", mwk_func,
                                  false);
            } else {
                set_errorResponse(rc, WA_PEC_SERVICE_TOKEN_INVALID,
                                  "error parsing token", mwk_func, false);
            }
            return MWK_ERROR;
        }
        /* pull out subject from service token */
        req_cred->u.st = data->token.webkdc_service;
        req_cred->subject = req_cred->u.st.subject;
    } else if (strcmp(at, "krb5") == 0) {
        const char *req;
        int blen;
        char *bin_req, *client_principal;
        struct webauth_krb5 *kc;

        kc = mwk_get_webauth_krb5_ctxt(rc->ctx, rc->r, mwk_func);
        /* mwk_get_webauth_krb5_ctxt already logged error */
        if (kc == NULL) {
            return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                     "server failure", mwk_func, false);
        }

        req = get_elem_text(rc, e, mwk_func);
        if (req == NULL) {
            return MWK_ERROR;
        }

        bin_req = (char*)apr_palloc(rc->r->pool,
                                    apr_base64_decode_len(req));
        blen = apr_base64_decode(bin_req, req);

        status = webauth_krb5_read_auth(rc->ctx, kc, bin_req, blen,
                                        rc->sconf->keytab_path,
                                        rc->sconf->keytab_principal,
                                        &client_principal, 0);

        if (status != WA_ERR_NONE) {
            char *msg = mwk_webauth_error_message(rc->ctx, rc->r, status,
                                                  "webauth_krb5_read_auth",
                                                  NULL);
            set_errorResponse(rc, WA_PEC_REQUESTER_KRB5_CRED_INVALID, msg,
                              mwk_func, true);
            return MWK_ERROR;
        }
        req_cred->subject = apr_pstrcat(rc->r->pool, "krb5:", client_principal,
                                        NULL);
    } else {
        char *msg = apr_psprintf(rc->r->pool,
                                 "unknown <requesterCredential> type: %s",
                                 at);
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 msg, mwk_func, true);
    }

    /*
    *req_subject_out = apr_pstrcat(rc->r->pool, req_cred->type,
                                   ":", req_cred->subject, NULL);

    */
    *req_subject_out = req_cred->subject;
    return MWK_OK;
}


/*
 * parse a proxy-token, which should be base64-encoded.
 * logs all errors and generates errorResponse if need be.
 */
static enum mwk_status
parse_webkdc_proxy_token(MWK_REQ_CTXT *rc, char *token,
                         struct webauth_token_webkdc_proxy *pt)
{
    static const char *mwk_func = "parse_webkdc_proxy_token";
    int status;
    struct webauth_token *data;

    if (!ensure_keyring_loaded(rc))
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE, "no keyring",
                                 mwk_func, true);
    status = webauth_token_decode(rc->ctx, WA_TOKEN_WEBKDC_PROXY, token,
                                  rc->sconf->ring, &data);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->ctx, rc->r->server, status, mwk_func,
                              "webauth_token_decode", NULL);
        if (status == WA_ERR_TOKEN_EXPIRED) {
            set_errorResponse(rc, WA_PEC_SERVICE_TOKEN_EXPIRED,
                              "proxy token was expired",
                              mwk_func, false);
        } else if (status == WA_ERR_BAD_HMAC) {
            set_errorResponse(rc, WA_PEC_SERVICE_TOKEN_INVALID,
                              "can't decrypt proxy token", mwk_func, false);
        } else {
            set_errorResponse(rc, WA_PEC_SERVICE_TOKEN_INVALID,
                              "error parsing token", mwk_func, false);
        }
        return MWK_ERROR;
    }
    *pt = data->token.webkdc_proxy;
    return MWK_OK;
}


static enum mwk_status
parse_login_token(MWK_REQ_CTXT *rc, char *token,
                  struct webauth_token_login *lt)
{
    static const char *mwk_func = "parse_login_token";
    int status;
    struct webauth_token *data;

    if (!ensure_keyring_loaded(rc))
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE, "no keyring",
                                 mwk_func, true);
    status = webauth_token_decode(rc->ctx, WA_TOKEN_LOGIN, token,
                                  rc->sconf->ring, &data);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->ctx, rc->r->server, status, mwk_func,
                              "webauth_token_decode", NULL);
        if (status == WA_ERR_TOKEN_EXPIRED) {
            set_errorResponse(rc, WA_PEC_SERVICE_TOKEN_EXPIRED,
                              "login token was expired",
                              mwk_func, false);
        } else if (status == WA_ERR_BAD_HMAC) {
            set_errorResponse(rc, WA_PEC_SERVICE_TOKEN_INVALID,
                              "can't decrypt login token", mwk_func, false);
        } else {
            set_errorResponse(rc, WA_PEC_SERVICE_TOKEN_INVALID,
                              "error parsing token", mwk_func, false);
        }
        return MWK_ERROR;
    }
    *lt = data->token.login;
    return MWK_OK;
}


/*
 */
static enum mwk_status
parse_subjectCredential(MWK_REQ_CTXT *rc, apr_xml_elem *e,
                        MWK_SUBJECT_CREDENTIAL *sub_cred,
                        size_t *num_proxy_tokens,
                        MWK_RETURNED_PROXY_TOKEN *rptokens)
{
    static const char*mwk_func = "parse_subjectCredential";

    const char *at = get_attr_value(rc, e, "type",  1, mwk_func);

    if (at == NULL) {
        return MWK_ERROR;
    }

    sub_cred->type = apr_pstrdup(rc->r->pool, at);

    if (strcmp(at, "proxy") == 0) {
        int n  = 0;
        apr_xml_elem *child;
        /* attempt to parse each proxy token */
        for (child = e->first_child; child; child = child->next) {
            if (strcmp(child->name, "proxyToken") == 0) {
                char *token = get_elem_text(rc, child, mwk_func);
                if (token == NULL)
                    return MWK_ERROR;
                if (!parse_webkdc_proxy_token(rc, token,
                                              &sub_cred->u.proxy.pt[n])) {
                    if (rptokens != NULL) {
                        /* caller wants us to accumulate bad proxy-tokens
                           instead of bailing */
                        const char *type = get_attr_value(rc, child, "type",
                                                          0, mwk_func);
                        if (type != NULL) {
                            /* cause the front-end to nuke the cookie */
                            rptokens[*num_proxy_tokens].token_data = "";
                            rptokens[*num_proxy_tokens].type = type;
                            *num_proxy_tokens = *num_proxy_tokens + 1;
                        }
                    } else {
                        return MWK_ERROR;
                    }
                } else {
                    n++;
                }
            } else {
                unknown_element(rc, mwk_func, e->name, child->name);
                return MWK_ERROR;
            }
        }
        sub_cred->u.proxy.num_proxy_tokens = n;
    } else if (strcmp(at, "login") == 0) {
        char *token;
        apr_xml_elem *login_token = get_element(rc, e,
                                                "loginToken", 1, mwk_func);
        if (login_token == NULL)
            return MWK_ERROR;

        token = get_elem_text(rc, login_token, mwk_func);
        if (token == NULL) {
            return MWK_ERROR;
        }

        if (!parse_login_token(rc, token, &sub_cred->u.lt)) {
            return MWK_ERROR;
        }
    } else {
        char *msg = apr_psprintf(rc->r->pool,
                                 "unknown <subjectCredential> type: %s",
                                 at);
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg,
                                 mwk_func, true);
    }
    return MWK_OK;
}

static enum mwk_status
make_token(MWK_REQ_CTXT *rc, struct webauth_token *data, const char **token,
           const char *mwk_func)
{
    int status;

    if (!ensure_keyring_loaded(rc))
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "no keyring", mwk_func, true);
    status = webauth_token_encode(rc->ctx, data, rc->sconf->ring, token);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->ctx, rc->r->server, status, mwk_func,
                              "webauth_token_create", NULL);
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "token create failed", mwk_func, false);
    }
    return MWK_OK;
}


static enum mwk_status
make_token_with_key(MWK_REQ_CTXT *rc, const void *key, size_t key_len,
                    struct webauth_token *data, const char **token,
                    const char *mwk_func)
{
    int status;
    struct webauth_keyring *ring;
    struct webauth_key *wkey;

    status = webauth_key_create(rc->ctx, WA_KEY_AES, key_len, key, &wkey);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->ctx, rc->r->server, status, mwk_func,
                              "webauth_key_create", NULL);
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "invalid key while creating token",
                                 mwk_func, true);
    }
    ring = webauth_keyring_from_key(rc->ctx, wkey);
    status = webauth_token_encode(rc->ctx, data, ring, token);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->ctx, rc->r->server, status, mwk_func,
                              "webauth_token_create", NULL);
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "token create failed", mwk_func, false);
    }
    return MWK_OK;
}

static enum mwk_status
create_service_token_from_req(MWK_REQ_CTXT *rc,
                              MWK_REQUESTER_CREDENTIAL *req_cred,
                              MWK_RETURNED_TOKEN *rtoken)
{
    static const char *mwk_func = "create_service_token_from_req";
    int status;
    size_t len;
    enum mwk_status ms;
    time_t expiration;
    struct webauth_token token;
    struct webauth_key *key;

    /* only create service tokens from krb5 creds */
    if (strcmp(req_cred->type, "krb5") != 0) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "can only create service-tokens with "
                                 "<requesterCredential> of type krb",
                                 mwk_func, true);
    }

    if (!mwk_has_service_access(rc, req_cred->subject)) {
        return set_errorResponse(rc, WA_PEC_UNAUTHORIZED,
                                 "not authorized to get a service token",
                                 mwk_func, true);
    }

    status = webauth_key_create(rc->ctx, WA_KEY_AES, WA_AES_128, NULL, &key);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->ctx, rc->r->server, status, mwk_func,
                              "webauth_create_key", NULL);
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "can't generate session key", mwk_func,
                                 false);
    }

    memset(&token, 0, sizeof(token));
    expiration = time(NULL) + rc->sconf->service_lifetime;
    token.type = WA_TOKEN_WEBKDC_SERVICE;
    token.token.webkdc_service.subject = req_cred->subject;
    token.token.webkdc_service.session_key = key->data;
    token.token.webkdc_service.session_key_len = key->length;
    token.token.webkdc_service.expiration = expiration;
    ms = make_token(rc, &token, &rtoken->token_data, mwk_func);

    if (!ms)
        return MWK_ERROR;

    rtoken->expires = apr_psprintf(rc->r->pool, "%lu",
                                   (unsigned long) expiration);

    len = key->length;
    rtoken->session_key = apr_palloc(rc->r->pool, apr_base64_encode_len(len));
    apr_base64_encode(rtoken->session_key, (char *) key->data, len);

    rtoken->subject = req_cred->subject;
    rtoken->info = " type=service";

    return MWK_OK;
}


/*
 * sad is allocated from request pool
 */
static enum mwk_status
get_krb5_sad(MWK_REQ_CTXT *rc,
             MWK_REQUESTER_CREDENTIAL *req_cred,
             struct webauth_token_webkdc_proxy *sub_pt,
             void **sad,
             size_t *sad_len,
             const char *mwk_func)
{
    struct webauth_krb5 *kc;
    int status;
    const char *server_principal;
    enum mwk_status ms;

    kc = mwk_get_webauth_krb5_ctxt(rc->ctx, rc->r, mwk_func);
    if (kc == NULL) {
        /* mwk_get_webauth_krb5_ctxt already logged error */
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                      "server failure (webauth_krb5_new)",
                                      mwk_func, false);
    }

    status = webauth_krb5_import_cred(rc->ctx, kc, sub_pt->data,
                                      sub_pt->data_len, NULL);

    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->ctx, rc->r,
                                              status,
                                              "webauth_krb5_import_cred",
                                              NULL);
        /* FIXME: probably need to examine errors a little more closely
         *        to determine if we should return a proxy-token error
         *        or a server-failure.
         */
        return set_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID, msg,
                                 mwk_func, true);
    }

    server_principal = req_cred->u.st.subject;
    if (strncmp(server_principal, "krb5:", 5) == 0) {
        server_principal += 5;
    }

    status = webauth_krb5_make_auth(rc->ctx, kc, server_principal, sad,
                                    sad_len);

    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->ctx, rc->r, status,
                                              "webauth_krb5_mk_req", NULL);
        /* FIXME: probably need to examine errors a little more closely
         *        to determine if we should return a proxy-token error
         *        or a server-failure.
         */
        set_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID, msg, mwk_func, true);
        ms = MWK_ERROR;
    } else {
        ms = MWK_OK;
    }
    return ms;
}


/*
 */
static enum mwk_status
create_id_token_from_req(MWK_REQ_CTXT *rc,
                         const char *auth_type,
                         MWK_REQUESTER_CREDENTIAL *req_cred,
                         MWK_SUBJECT_CREDENTIAL *sub_cred,
                         MWK_RETURNED_TOKEN *rtoken,
                         const char **subject_out)
{
    static const char *mwk_func = "create_id_token_from_req";
    size_t sad_len;
    enum mwk_status ms;
    struct webauth_token_webkdc_proxy *sub_pt;
    struct webauth_token token;
    void *sad;

    /* make sure auth_type is not NULL */
    if (auth_type == NULL) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "auth type is NULL",
                                 mwk_func, true);
    }

    /* only create id tokens from service creds */
    if (strcmp(req_cred->type, "service") != 0) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "can only create id-tokens with "
                                 "<requesterCredential> of type service",
                                 mwk_func, true);
    }

    /* make sure we have a subject cred with a type='proxy' */
    if (strcmp(sub_cred->type, "proxy") != 0) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "can only create id-tokens with "
                                 "<subjectCredential> of type proxy",
                                 mwk_func, true);
    }

    /* check access */
    if (!mwk_has_id_access(rc, req_cred->subject)) {
        return set_errorResponse(rc, WA_PEC_UNAUTHORIZED,
                                 "not authorized to get an id token",
                                 mwk_func, true);
    }

    sad = NULL;
    if (strcmp(auth_type, "webkdc") == 0) {
        /* check krb5 or remuser */
        sub_pt = find_proxy_token(rc, sub_cred, "krb5", mwk_func, 0);
        if (sub_pt == NULL)
            sub_pt = find_proxy_token(rc, sub_cred, "remuser", mwk_func, 0);
        if (sub_pt == NULL) {
            set_errorResponse(rc, WA_PEC_PROXY_TOKEN_REQUIRED,
                              "need a proxy-token", mwk_func, true);
            return MWK_ERROR;
        }
    } else if (strcmp(auth_type, "krb5") == 0) {
        /* find a proxy-token of the right type */
        sub_pt = find_proxy_token(rc, sub_cred, "krb5", mwk_func, 1);
        if (sub_pt == NULL)
            return MWK_ERROR;
        if (!get_krb5_sad(rc, req_cred, sub_pt, &sad, &sad_len, mwk_func)) {
            return MWK_ERROR;
        }

    } else {
        char *msg = apr_psprintf(rc->r->pool, "invalid authenticator type %s",
                                 auth_type);
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg, mwk_func,
                                 true);
    }

    /* check access again */
    if (!mwk_can_use_proxy_token(rc, req_cred->subject,
                                 sub_pt->proxy_subject)) {
        return set_errorResponse(rc, WA_PEC_UNAUTHORIZED,
                                 "not authorized to use proxy token",
                                 mwk_func, true);
    }

    /*
     * Expiration, initial credentials, and level of assurance come from the
     * corresponding fields of the proxy-token.
     */
    memset(&token, 0, sizeof(token));
    token.type = WA_TOKEN_ID;
    token.token.id.subject = sub_pt->subject;
    token.token.id.auth = auth_type;
    if (sad != NULL) {
        token.token.id.auth_data = sad;
        token.token.id.auth_data_len = sad_len;
    }
    token.token.id.expiration = sub_pt->expiration;
    if (sub_pt->initial_factors != NULL)
        token.token.id.initial_factors = sub_pt->initial_factors;
    if (sub_pt->loa > 0)
        token.token.id.loa = sub_pt->loa;

    /* FIXME: Hardcoded for now, needs to come from the proxy token origin. */
    token.token.id.session_factors = "u";

    ms = make_token_with_key(rc, req_cred->u.st.session_key,
                             req_cred->u.st.session_key_len, &token,
                             &rtoken->token_data, mwk_func);

    rtoken->subject = sub_pt->subject;
    rtoken->info =
        apr_pstrcat(rc->r->pool, " type=id sa=", auth_type, NULL);

    if (subject_out)
        *subject_out = rtoken->subject;

    return ms;
}


/*
 */
static enum mwk_status
create_cred_token_from_req(MWK_REQ_CTXT *rc,
                           apr_xml_elem *e,
                           MWK_REQUESTER_CREDENTIAL *req_cred,
                           MWK_SUBJECT_CREDENTIAL *sub_cred,
                           MWK_RETURNED_TOKEN *rtoken)
{
    static const char *mwk_func = "create_cred_token_from_req";
    size_t ticket_len;
    int status;
    time_t expiration, ticket_expiration;
    apr_xml_elem *credential_type, *server_principal;
    char *ct, *sp;
    struct webauth_krb5 *kc;
    struct webauth_token_webkdc_proxy *sub_pt;
    struct webauth_token token;
    void *ticket;
    enum mwk_status ms;

    /* only create cred tokens from service creds */
    if (strcmp(req_cred->type, "service") != 0 ) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "can only create cred-tokens with "
                                 "<requesterCredential> of type service",
                                 mwk_func, true);
    }

    /* make sure we have a subject cred with a type='proxy' */
    if (strcmp(sub_cred->type, "proxy") != 0) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "can only create cred-tokens with "
                                 "<subjectCredential> of type proxy",
                                 mwk_func, true);
    }

    credential_type = get_element(rc, e, "credentialType", 1, mwk_func);
    if (credential_type == NULL)
        return MWK_ERROR;
    ct = get_elem_text(rc, credential_type, mwk_func);
    if (ct == NULL)
        return MWK_ERROR;
    server_principal = get_element(rc, e, "serverPrincipal", 1, mwk_func);
    if (server_principal == NULL)
        return MWK_ERROR;
    sp = get_elem_text(rc, server_principal, mwk_func);
    if (sp == NULL)
        return MWK_ERROR;

    /* check access */
    if (!mwk_has_cred_access(rc, req_cred->subject, ct, sp)) {
        return set_errorResponse(rc, WA_PEC_UNAUTHORIZED,
                                 "not authorized to get credential",
                                 mwk_func, true);
    }

    /* make sure we are creating a cred-token that has
       the same type as the proxy-token we are using to create it */
    sub_pt = find_proxy_token(rc, sub_cred, ct, mwk_func, 1);
    if (sub_pt == NULL)
        return MWK_ERROR;

    /* check access again */
    if (!mwk_can_use_proxy_token(rc, req_cred->subject,
                                 sub_pt->proxy_subject)) {
        return set_errorResponse(rc, WA_PEC_UNAUTHORIZED,
                                 "not authorized to use proxy token",
                                 mwk_func, true);
    }

    /* try to get the credentials  */
    kc = mwk_get_webauth_krb5_ctxt(rc->ctx, rc->r, mwk_func);
    if (kc == NULL) {
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                      "server failure", mwk_func, false);
    }

    status = webauth_krb5_import_cred(rc->ctx, kc, sub_pt->data,
                                      sub_pt->data_len, NULL);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->ctx, rc->r,
                                              status,
                                              "webauth_krb5_init_via_cred",
                                              NULL);
        /* FIXME: probably need to examine errors a little more closely
         *        to determine if we should return a proxy-token error
         *        or a server-failure.
         */
        return set_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID, msg,
                                 mwk_func, true);
    }

    /* now try and export a ticket */
    status = webauth_krb5_export_cred(rc->ctx, kc, sp, &ticket, &ticket_len,
                                      &ticket_expiration);

    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->ctx, rc->r,
                                              status,
                                              "webauth_krb5_export_ticket",
                                              NULL);
        return set_errorResponse(rc, WA_PEC_GET_CRED_FAILURE,
                                 msg, mwk_func, true);
    }


    /* now create the cred-token */
    if (ticket_expiration < sub_pt->expiration)
        expiration = ticket_expiration;
    else
        expiration = sub_pt->expiration;
    memset(&token, 0, sizeof(token));
    token.type = WA_TOKEN_CRED;
    token.token.cred.subject = sub_pt->subject;
    token.token.cred.type = ct;
    token.token.cred.service = sp;
    token.token.cred.data = ticket;
    token.token.cred.data_len = ticket_len;
    token.token.cred.expiration = expiration;

    ms = make_token_with_key(rc, req_cred->u.st.session_key,
                             req_cred->u.st.session_key_len, &token,
                             &rtoken->token_data, mwk_func);

    rtoken->subject = sub_pt->subject;
    rtoken->info =
        apr_pstrcat(rc->r->pool, " type=cred crt=", ct, " crs=", sp,NULL);

    return ms;
}

/*
 * parse a <requestToken> from a POST, which should be base64-encoded.
 * return 1 on success, 0 on error.
 * logs all errors and generates errorResponse if need be.
 */
static enum mwk_status
parse_request_token(MWK_REQ_CTXT *rc, const char *token,
                    const struct webauth_token_webkdc_service *st,
                    struct webauth_token_request **rt)
{
    int status;
    struct webauth_token *data;
    struct webauth_key *key;
    const struct webauth_keyring *ring;
    time_t expiration;
    static const char *mwk_func = "parse_request_token";

    if (token == NULL) {
        return set_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID,
                                 "request token is NULL", mwk_func, true);
    }
    status = webauth_key_create(rc->ctx, WA_KEY_AES, st->session_key_len,
                                st->session_key, &key);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->ctx, rc->r->server, status, mwk_func,
                              "webauth_key_create", NULL);
        return set_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID,
                                 "invalid service token key", mwk_func, true);
    }
    ring = webauth_keyring_from_key(rc->ctx, key);
    status = webauth_token_decode(rc->ctx, WA_TOKEN_REQUEST, token, ring,
                                  &data);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->ctx, rc->r->server, status, mwk_func,
                              "webauth_token_parse", NULL);
        if (status == WA_ERR_BAD_HMAC) {
            set_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID,
                              "can't decrypt request token", mwk_func, false);
        } else {
            set_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID,
                              "error parsing token", mwk_func, false);
        }
        return MWK_ERROR;
    }

    /* Copy the token and do some additional checks. */
    *rt = &data->token.request;
    expiration = (*rt)->creation + rc->sconf->token_max_ttl;
    if (expiration < time(NULL)) {
        set_errorResponse(rc, WA_PEC_REQUEST_TOKEN_STALE,
                          "request token was stale", mwk_func, false);
        return MWK_ERROR;
    }
    return MWK_OK;
}


static enum mwk_status
handle_getTokensRequest(MWK_REQ_CTXT *rc, apr_xml_elem *e,
                        const char **req_subject_out,
                        const char **subject_out)
{
    apr_xml_elem *child, *tokens, *token;
    static const char *mwk_func="handle_getTokensRequest";
    const char *mid = NULL;
    char *request_token;
    struct webauth_token_request *req_token = NULL;
    MWK_REQUESTER_CREDENTIAL req_cred;
    MWK_SUBJECT_CREDENTIAL sub_cred;
    int req_cred_parsed = 0;
    int sub_cred_parsed = 0;
    size_t num_tokens, i;

    MWK_RETURNED_TOKEN rtokens[MAX_TOKENS_RETURNED];

    *subject_out = "<unknown>";
    *req_subject_out = "<unknown>";
    tokens = NULL;
    request_token = NULL;
    memset(&req_cred, 0, sizeof(req_cred));
    memset(&sub_cred, 0, sizeof(sub_cred));

    /* walk through each child element in <getTokensRequest> */
    for (child = e->first_child; child; child = child->next) {
        if (strcmp(child->name, "requesterCredential") == 0) {
            if (!parse_requesterCredential(rc, child, &req_cred,
                                           req_subject_out))
                return MWK_ERROR;
            req_cred_parsed = 1;
        } else if (strcmp(child->name, "subjectCredential") == 0) {
            if (!parse_subjectCredential(rc, child, &sub_cred, NULL, NULL))
                return MWK_ERROR;
            sub_cred_parsed = 1;
        } else if (strcmp(child->name, "messageId") == 0) {
            mid = get_elem_text(rc, child, mwk_func);
            if (mid == NULL)
                return MWK_ERROR;
        } else if (strcmp(child->name, "requestToken") == 0) {
            request_token = get_elem_text(rc, child, mwk_func);
            if (request_token == NULL)
                return MWK_ERROR;
        } else if (strcmp(child->name, "tokens") == 0) {
            tokens = child;
        } else {
            unknown_element(rc, mwk_func, e->name, child->name);
            return MWK_ERROR;
        }
    }

    /* make sure we found some tokens */
    if (tokens == NULL) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "missing <tokens> in getTokensRequest",
                                 mwk_func, true);
    }

    /* make sure we found requesterCredential */
    if (!req_cred_parsed) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                          "missing <requesterCredential> in getTokensRequest",
                          mwk_func, true);
    }

    /* make sure sub_cred looks ok if its present */
    if (sub_cred_parsed && strcmp(sub_cred.type, "proxy") != 0) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "<subjectCredential> should be of type proxy",
                                 mwk_func, true);
    }

    /* if req_cred is of type "service", compare command name */
    if (strcmp(req_cred.type, "service") == 0) {

        /* make sure we found requestToken */
        if (request_token == NULL) {
            return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                   "missing <requestToken>",
                                   mwk_func, true);
        }
        /* parse request_token */
        if (!parse_request_token(rc, request_token, &req_cred.u.st,
                                 &req_token)) {
            return MWK_ERROR;
        }

        if (req_token->command == NULL
            || strcmp(req_token->command, "getTokensRequest") != 0) {
            return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                     "xml command in request-token "
                                     "doesn't match",
                                     mwk_func, true);
        }
    }

    num_tokens = 0;
    /* plow through each <token> in <tokens> */
    for (token = tokens->first_child; token; token = token->next) {
        const char *tt;

        if (strcmp(token->name, "token") != 0) {
            unknown_element(rc, mwk_func, tokens->name, token->name);
            return MWK_ERROR;
        }

        if (num_tokens == MAX_TOKENS_RETURNED) {
            return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                     "too many tokens requested",
                                     mwk_func, true);
        }

        rtokens[num_tokens].session_key = NULL;
        rtokens[num_tokens].expires = NULL;
        rtokens[num_tokens].token_data = NULL;
        rtokens[num_tokens].subject = "<unknown>";
        rtokens[num_tokens].id = get_attr_value(rc, token, "id", 0, mwk_func);
        rtokens[num_tokens].info = "";

        tt = get_attr_value(rc, token, "type", 1, mwk_func);
        if (tt == NULL)
            return MWK_ERROR;

        /* make sure we found subjectCredential if requesting
         * a token type other then "sevice".
         */
        if (strcmp(tt, "service") !=0 && !sub_cred_parsed) {
            return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                     "missing <subjectCredential> "
                                     "in getTokensRequest",
                                     mwk_func, true);
        }

        if (strcmp(tt, "service") == 0) {
            if (!create_service_token_from_req(rc, &req_cred,
                                               &rtokens[num_tokens])) {
                return MWK_ERROR;
            }

        } else if (strcmp(tt, "id") == 0) {
            const char *at;
            apr_xml_elem *auth;

            auth = get_element(rc, token, "authenticator", 1, mwk_func);
            if (auth == NULL)
                return MWK_ERROR;
            at = get_attr_value(rc, auth, "type", 1, mwk_func);
            if (at == NULL)
                return MWK_ERROR;

            if (!create_id_token_from_req(rc, at, &req_cred, &sub_cred,
                                          &rtokens[num_tokens], NULL)) {
                return MWK_ERROR;
            }
        } else if (strcmp(tt, "cred") == 0) {
            if (!create_cred_token_from_req(rc, token, &req_cred, &sub_cred,
                                            &rtokens[num_tokens])) {
                return MWK_ERROR;
            }
        } else {
            char *msg = apr_psprintf(rc->r->pool,
                                     "unknown token type: %s", tt);
            return set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg,
                                     mwk_func, true);
        }
        num_tokens++;
    }

    /* if we got here, we made it! */
    ap_rvputs(rc->r, "<getTokensResponse><tokens>", NULL);

    for (i = 0; i < num_tokens; i++) {
        if (i==0)
            *subject_out = (char*)rtokens[0].subject;

        if (rtokens[i].id != NULL) {
            ap_rprintf(rc->r, "<token id=\"%s\">",
                        apr_xml_quote_string(rc->r->pool, rtokens[i].id, 1));
        } else {
            ap_rvputs(rc->r, "<token>", NULL);
        }
        /* don't have to quote these, since they are base64'd data
           or numeric strings */
        ap_rvputs(rc->r,"<tokenData>", rtokens[i].token_data,
                  "</tokenData>", NULL);
        if (rtokens[i].session_key) {
            ap_rvputs(rc->r,"<sessionKey>", rtokens[i].session_key,
                  "</sessionKey>", NULL);
        }
        if (rtokens[i].expires) {
            ap_rvputs(rc->r,"<expires>", rtokens[i].expires,
                      "</expires>", NULL);
        }
        ap_rvputs(rc->r, "</token>", NULL);


        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, rc->r->server,
                     "mod_webkdc: event=getTokens from=%s "
                     "server=%s user=%s%s",
                     rc->r->useragent_ip,
                     *req_subject_out,
                     rtokens[i].subject,
                     rtokens[i].info);
    }
    ap_rvputs(rc->r, "</tokens></getTokensResponse>", NULL);
    ap_rflush(rc->r);

    return MWK_OK;
}

/*
 * Check that the realm of the authenticated principal is in the list of
 * permitted realms, or that the list of realms is empty.  Returns MWK_OK if
 * the realm is permitted, MWK_ERROR otherwise.  Sets the error on a failure,
 * so the caller doesn't need to do so.
 */
static int
realm_permitted(MWK_REQ_CTXT *rc, struct webauth_krb5 *kc,
                const char *mwk_func)
{
    int status;
    char *realm;
    apr_array_header_t *realms;
    char **allowed;
    int okay = 0;

    /* If we aren't restricting the realms, always return true. */
    if (rc->sconf->permitted_realms->nelts <= 0)
        return MWK_OK;

    /* Get the realm. */
    status = webauth_krb5_get_realm(rc->ctx, kc, &realm);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->ctx, rc->r, status,
                                             "webauth_krb5_get_realm", NULL);
        set_errorResponse(rc, WA_PEC_SERVER_FAILURE, msg, mwk_func, true);
        return MWK_ERROR;
    }
    realms = apr_array_copy(rc->r->pool, rc->sconf->permitted_realms);
    while ((allowed = apr_array_pop(realms)) != NULL)
        if (apr_strnatcmp(*allowed, realm) == 0) {
            okay = 1;
            break;
        }
    if (okay == 0) {
        char *msg = apr_psprintf(rc->r->pool, "realm %s is not permitted",
                                 realm);
        set_errorResponse(rc, WA_PEC_USER_REJECTED, msg, mwk_func, true);
        return MWK_ERROR;
    }
    return MWK_OK;
}

/*
 * Get the subject (the authenticated identity).  This is where we do local
 * realm conversion if requested or strip off the realm if requested to do so.
 * Returns MWK_OK if we successfully set the subject and MWK_ERROR otherwise.
 * Sets the error on a failure, so the caller doesn't need to do so.
 *
 * The subject is returned as newly allocated pool memory.
 */
static int
get_subject(MWK_REQ_CTXT *rc, struct webauth_krb5 *kc,
            char **subject, const char *mwk_func)
{
    enum webauth_krb5_canon canonicalize = WA_KRB5_CANON_LOCAL;
    int status;

    /*
     * If WebKdcLocalRealms was set, it may be set to a keyword or to a list
     * of realms.  "local" is the default, but recognize it explicitly as
     * well.  If the first element is neither "none" nor "local," treat it as
     * a list of realms.
     */
    if (rc->sconf->local_realms->nelts > 0) {
        apr_array_header_t *realms;
        char *realm;
        char **local;

        realms = apr_array_copy(rc->r->pool, rc->sconf->local_realms);
        local = apr_array_pop(realms);
        if (apr_strnatcmp(*local, "none") == 0) {
            canonicalize = WA_KRB5_CANON_NONE;
        } else if (apr_strnatcmp(*local, "local") == 0) {
            canonicalize = WA_KRB5_CANON_LOCAL;
        } else {
            canonicalize = WA_KRB5_CANON_NONE;
            status = webauth_krb5_get_realm(rc->ctx, kc, &realm);
            if (status != WA_ERR_NONE) {
                char *msg = mwk_webauth_error_message(rc->ctx, rc->r, status,
                                                      "webauth_krb5_get_realm",
                                                      NULL);
                set_errorResponse(rc, WA_PEC_SERVER_FAILURE, msg, mwk_func,
                                  true);
                return MWK_ERROR;
            }
            do {
                if (apr_strnatcmp(*local, realm) == 0)
                    canonicalize = WA_KRB5_CANON_STRIP;
            } while ((local = apr_array_pop(realms)) != NULL);
        }
    }

    /*
     * We now know the canonicalization method we're using, so we can retrieve
     * the principal from the context.
     */
    status = webauth_krb5_get_principal(rc->ctx, kc, subject, canonicalize);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->ctx, rc->r, status,
                                             "webauth_krb5_get_principal",
                                              NULL);
        set_errorResponse(rc, WA_PEC_SERVER_FAILURE, msg, mwk_func, true);
        return MWK_ERROR;
    }
    return MWK_OK;
}


/*
 * Parses a <requesterCredential> XML element containing a service token and
 * stores it in the provided webauth_webkdc_login_request struct after
 * decoding it and confirming that it's the right type.  Use
 * parse_requesterCredential to support either service or krb5 credentials.
 */
static enum mwk_status
parse_service_token(MWK_REQ_CTXT *rc, apr_xml_elem *e,
                    struct webauth_webkdc_login_request *request,
                    struct webauth_token_webkdc_service **service)
{
    static const char *mwk_func = "parse_service_token";
    int status;
    struct webauth_token *data;
    const char *at = get_attr_value(rc, e, "type", 1, mwk_func);
    char *msg, *token;

    if (!ensure_keyring_loaded(rc))
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE, "no keyring",
                                 mwk_func, true);

    /* Make sure that the provided token type is service. */
    if (at == NULL)
        return MWK_ERROR;
    if (strcmp(at, "service") != 0) {
        msg = apr_psprintf(rc->r->pool, "unknown <requesterCredential> type:"
                           " %s", at);
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg, mwk_func,
                                 true);
    }

    token = get_elem_text(rc, e, mwk_func);
    if (token == NULL)
        return MWK_ERROR;
    status = webauth_token_decode(rc->ctx, WA_TOKEN_WEBKDC_SERVICE, token,
                                  rc->sconf->ring, &data);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->ctx, rc->r->server, status, mwk_func,
                              "webauth_token_decode", NULL);
        if (status == WA_ERR_TOKEN_EXPIRED) {
            set_errorResponse(rc, WA_PEC_SERVICE_TOKEN_EXPIRED,
                              "service token was expired",
                              mwk_func, false);
        } else if (status == WA_ERR_BAD_HMAC) {
            set_errorResponse(rc, WA_PEC_SERVICE_TOKEN_INVALID,
                              "can't decrypt service token", mwk_func,
                              false);
        } else {
            set_errorResponse(rc, WA_PEC_SERVICE_TOKEN_INVALID,
                              "error parsing token", mwk_func, false);
        }
        return MWK_ERROR;
    }
    request->service = token;
    *service = &data->token.webkdc_service;
    return MWK_OK;
}


/*
 * Parse a <subjectCredential> XML element passed in to <requestTokenRequest>
 * into a webauth_webkdc_login_request struct.  Use parse_subjectCredential
 * for <getTokens> for right now.
 */
static enum mwk_status
parse_subject_credentials(MWK_REQ_CTXT *rc, apr_xml_elem *e,
                         struct webauth_webkdc_login_request *request)
{
    static const char *mwk_func = "parse_subject_credentials";
    apr_xml_elem *child;
    apr_xml_attr *a;
    char *data;
    apr_array_header_t *wkproxies, *wkfactors, *logins;
    struct webauth_webkdc_proxy_data *pd;
    size_t size;

    size = sizeof(struct webauth_webkdc_proxy_data);
    wkproxies = apr_array_make(rc->r->pool, 1, size);
    wkfactors = apr_array_make(rc->r->pool, 1, sizeof(const char *));
    logins    = apr_array_make(rc->r->pool, 1, sizeof(const char *));
    for (child = e->first_child; child != NULL; child = child->next) {
        if (strcmp(child->name, "proxyToken") == 0) {
            data = get_elem_text(rc, child, mwk_func);
            if (data == NULL)
                return MWK_ERROR;
            pd = &APR_ARRAY_PUSH(wkproxies, struct webauth_webkdc_proxy_data);
            pd->token = data;
            for (a = child->attr; a != NULL; a = a->next)
                if (strcmp(a->name, "source") == 0) {
                    pd->source = a->value;
                    break;
                }
        } else if (strcmp(child->name, "loginToken") == 0) {
            data = get_elem_text(rc, child, mwk_func);
            if (data == NULL)
                return MWK_ERROR;
            APR_ARRAY_PUSH(logins, const char *) = data;
        } else if (strcmp(child->name, "factorToken") == 0) {
            data = get_elem_text(rc, child, mwk_func);
            if (data == NULL)
                return MWK_ERROR;
            APR_ARRAY_PUSH(wkfactors, const char *) = data;
        } else {
            unknown_element(rc, mwk_func, e->name, child->name);
            return MWK_ERROR;
        }
    }
    request->wkproxies = wkproxies;
    request->wkfactors = wkfactors;
    request->logins    = logins;
    return MWK_OK;
}


static enum mwk_status
parse_requestInfo(MWK_REQ_CTXT *rc, apr_xml_elem *e,
                  struct webauth_webkdc_login_request *request)
{
    static const char *mwk_func = "parse_requestInfo";
    apr_xml_elem *ie;

    for (ie = e->first_child; ie; ie = ie->next) {
        if (strcmp(ie->name, "localIpAddr") == 0) {
            request->local_ip = get_elem_text(rc, ie, mwk_func);
            if (request->local_ip == NULL)
                return MWK_ERROR;
        } else if (strcmp(ie->name, "localIpPort") == 0) {
            request->local_port = get_elem_text(rc, ie, mwk_func);
            if (request->local_port == NULL)
                return MWK_ERROR;
        } else if (strcmp(ie->name, "remoteIpAddr") == 0) {
            request->remote_ip = get_elem_text(rc, ie, mwk_func);
            if (request->remote_ip == NULL)
                return MWK_ERROR;
        } else if (strcmp(ie->name, "remoteIpPort") == 0) {
            request->remote_port = get_elem_text(rc, ie, mwk_func);
            if (request->remote_port == NULL)
                return MWK_ERROR;
        } else if (strcmp(ie->name, "remoteUser") == 0) {
            request->remote_user = get_elem_text(rc, ie, mwk_func);
            if (request->remote_user == NULL)
                return MWK_ERROR;
        } else {
            unknown_element(rc, mwk_func, e->name, ie->name);
            return MWK_ERROR;
        }
    }
    if (request->remote_user == NULL
        && (request->local_ip == NULL ||
            request->local_port == NULL ||
            request->remote_ip == NULL ||
            request->remote_port == NULL)) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "<requestInfo> missing data",
                                 mwk_func, true);
    }
    return MWK_OK;
}


/*
 * Given the request context, an XML tag, and an array of const char *, print
 * out the contents of the array as a series of that XML element.  If the
 * array is NULL, prints out nothing.
 */
static void
print_xml_array(MWK_REQ_CTXT *rc, const char *tag,
                const apr_array_header_t *array)
{
    int i;
    const char *string;

    if (array == NULL)
        return;

    for (i = 0; i < array->nelts; i++) {
        string = APR_ARRAY_IDX(array, i, const char *);
        string = apr_xml_quote_string(rc->r->pool, string, false);
        ap_rprintf(rc->r, "<%s>%s</%s>", tag, string, tag);
    }
}


static enum mwk_status
handle_requestTokenRequest(MWK_REQ_CTXT *rc, apr_xml_elem *e,
                           const char **req_subject_out,
                           const char **subject_out)
{
    apr_xml_elem *child;
    static const char *mwk_func="handle_requestTokenRequest";
    void *ls_data;
    int i, status;
    struct webauth_webkdc_login_request request;
    struct webauth_webkdc_login_response *response;
    struct webauth_token_webkdc_service *service = NULL;
    struct webauth_token_request *req = NULL;

    /*
     * FIXME: These should be set to NULL, not <unknown>.  Chase down all the
     * places we assume they aren't NULL.
     */
    *subject_out = "<unknown>";
    *req_subject_out = "<unknown>";

    if (!ensure_keyring_loaded(rc))
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "no keyring", mwk_func, true);

    memset(&request, 0, sizeof(request));
    request.client_ip = rc->r->useragent_ip;

    /* walk through each child element in <requestTokenRequest> */
    for (child = e->first_child; child; child = child->next) {
        if (strcmp(child->name, "requesterCredential") == 0) {
            if (!parse_service_token(rc, child, &request, &service))
                return MWK_ERROR;
        } else if (strcmp(child->name, "subjectCredential") == 0) {
            if (!parse_subject_credentials(rc, child, &request))
                return MWK_ERROR;
        } else if (strcmp(child->name, "requestToken") == 0) {
            request.request = get_elem_text(rc, child, mwk_func);
            if (request.request == NULL)
                return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                         "invalid <requestToken>", mwk_func,
                                         true);
        } else if (strcmp(child->name, "authzSubject") == 0) {
            request.authz_subject = get_elem_text(rc, child, mwk_func);
            if (request.authz_subject == NULL)
                return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                         "invalid <authzSubject>", mwk_func,
                                         true);
        } else if (strcmp(child->name, "loginState") == 0) {
            request.login_state = get_elem_text(rc, child, mwk_func);
            if (request.login_state == NULL)
                return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                         "invalid <loginState>", mwk_func,
                                         true);
        } else if (strcmp(child->name, "requestInfo") == 0) {
            if (!parse_requestInfo(rc, child, &request))
                return MWK_ERROR;
        } else {
            unknown_element(rc, mwk_func, e->name, child->name);
            return MWK_ERROR;
        }
    }

    /* make sure we found requesterCredential */
    if (request.service == NULL || service == NULL)
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "missing <requesterCredential>",
                                 mwk_func, true);
    *req_subject_out = service->subject;

    /*
     * Make sure we found <subjectCredential>.  Note that the array may be
     * legitimately empty if the user has no proxy credentials and it's their
     * first visit to WebLogin.
     */
    if (request.wkproxies == NULL)
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "missing <subjectCredential>",
                                 mwk_func, true);

    /* make sure we found requestToken */
    if (request.request == NULL)
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "missing <requestToken>",
                                 mwk_func, true);
    if (!parse_request_token(rc, request.request, service, &req))
        return MWK_ERROR;

    /*
     * Based on the type of token requested, check that the requesting WAS is
     * permitted to get that type of token.
     */
    if (strcmp(req->type, "id") == 0) {
        if (!mwk_has_id_access(rc, service->subject))
            return set_errorResponse(rc, WA_PEC_UNAUTHORIZED,
                                     "not authorized to get an id token",
                                     mwk_func, true);
    } else if (strcmp(req->type, "proxy") == 0) {
        if (!mwk_has_proxy_access(rc, service->subject, req->proxy_type))
            return set_errorResponse(rc, WA_PEC_UNAUTHORIZED,
                                 "not authorized to get a proxy token",
                                 mwk_func, true);
    }

    /* need to base64 decode loginState */
    if (request.login_state != NULL) {
        ls_data = apr_palloc(rc->r->pool,
                             apr_base64_decode_len(request.login_state));
        apr_base64_decode(ls_data, request.login_state);
        request.login_state = ls_data;
    }

    /*
     * Call into libwebauth to process the login information.  This will take
     * the accumulated data in the request and attempt to fulfill it.  On
     * error, it will return a WebAuth status code and also fill in the
     * login_error and login_message fields.
     *
     * Some error messages still return a full <requestTokenResponse> so that
     * we can carry additional information.  The rest send an <errorResponse>.
     */
    status = webauth_webkdc_login(rc->ctx, &request, &response,
                                  rc->sconf->ring);
    if (status != WA_ERR_NONE
        && status != WA_PEC_AUTH_REJECTED
        && status != WA_PEC_LOA_UNAVAILABLE
        && status != WA_PEC_LOGIN_REJECTED
        && status != WA_PEC_MULTIFACTOR_REQUIRED
        && status != WA_PEC_MULTIFACTOR_UNAVAILABLE
        && status != WA_PEC_PROXY_TOKEN_REQUIRED)
        return set_errorResponse(rc, status,
                                 webauth_error_message(rc->ctx, status),
                                 mwk_func, true);

    /* Send the XML response. */
    ap_rvputs(rc->r, "<requestTokenResponse>", NULL);

    if (status != WA_ERR_NONE) {
        ap_rprintf(rc->r, "<loginErrorCode>%d</loginErrorCode>", status);
        ap_rprintf(rc->r, "<loginErrorMessage>%s</loginErrorMessage>",
                   apr_xml_quote_string(rc->r->pool,
                                        webauth_error_message(rc->ctx, status),
                                        false));
    }

    if (response->user_message != NULL)
        ap_rprintf(rc->r, "<userMessage><![CDATA[%s]]></userMessage>",
                   response->user_message);

    if (response->login_state != NULL) {
        char *out_login_state =
            apr_palloc(rc->r->pool,
                       apr_base64_encode_len(strlen(response->login_state)));
        apr_base64_encode(out_login_state, response->login_state,
                          strlen(response->login_state));
        ap_rvputs(rc->r,
                  "<loginState>", out_login_state , "</loginState>",
                  NULL);
    }

    if (response->factors_configured != NULL) {
        apr_array_header_t *wanted, *configured;

        wanted = webauth_factors_array(rc->ctx, response->factors_wanted);
        configured = webauth_factors_array(rc->ctx,
                                           response->factors_configured);
        ap_rvputs(rc->r, "<multifactorRequired>", NULL);
        print_xml_array(rc, "factor", wanted);
        print_xml_array(rc, "configuredFactor", configured);
        if (response->default_device != NULL
            || response->default_factor != NULL) {
            ap_rvputs(rc->r, "<defaultFactor>", NULL);
            if (response->default_device != NULL)
                ap_rprintf(rc->r, "<id>%s</id>",
                           apr_xml_quote_string(rc->r->pool,
                                                response->default_device,
                                                false));
            if (response->default_factor != NULL)
                ap_rprintf(rc->r, "<factor>%s</factor>",
                           response->default_factor);
            ap_rvputs(rc->r, "</defaultFactor>", NULL);
        }
        if (response->devices != NULL) {
            apr_array_header_t *factors;
            const apr_array_header_t *devices = response->devices;
            struct webauth_device *device;

            ap_rvputs(rc->r, "<devices>", NULL);
            for (i = 0; i < response->devices->nelts; i++) {
                device = &APR_ARRAY_IDX(devices, i, struct webauth_device);
                ap_rvputs(rc->r, "<device>", NULL);
                if (device->name != NULL)
                    ap_rprintf(rc->r, "<name>%s</name>",
                               apr_xml_quote_string(rc->r->pool, device->name,
                                                    false));
                if (device->id != NULL)
                    ap_rprintf(rc->r, "<id>%s</id>",
                               apr_xml_quote_string(rc->r->pool, device->id,
                                                    false));
                if (device->factors != NULL) {
                    factors = webauth_factors_array(rc->ctx, device->factors);
                    print_xml_array(rc, "factor", factors);
                }
                ap_rvputs(rc->r, "</device>", NULL);
            }
            ap_rvputs(rc->r, "</devices>", NULL);
        }
        ap_rvputs(rc->r, "</multifactorRequired>", NULL);
    }

    if (response->proxies != NULL) {
        struct webauth_webkdc_proxy_data *data;

        ap_rvputs(rc->r, "<proxyTokens>", NULL);
        for (i = 0; i < response->proxies->nelts; i++) {
            data = &APR_ARRAY_IDX(response->proxies, i,
                                  struct webauth_webkdc_proxy_data);
            ap_rvputs(rc->r, "<proxyToken type='", data->type, "'>",
                      data->token, "</proxyToken>", NULL);
        }
        ap_rvputs(rc->r, "</proxyTokens>", NULL);
    }

    if (response->factor_tokens != NULL) {
        struct webauth_webkdc_factor_data *data;

        ap_rvputs(rc->r, "<factorTokens>", NULL);
        for (i = 0; i < response->factor_tokens->nelts; i++) {
            data = &APR_ARRAY_IDX(response->factor_tokens, i,
                                  struct webauth_webkdc_factor_data);
            ap_rprintf(rc->r, "<factorToken expires='%lu'>%s</factorToken>",
                       (unsigned long) data->expiration, data->token);
        }
        ap_rvputs(rc->r, "</factorTokens>", NULL);
    }

    /* put out return-url */
    ap_rvputs(rc->r,"<returnUrl>",
              apr_xml_quote_string(rc->r->pool, response->return_url, 1),
              "</returnUrl>", NULL);

    /* requesterSubject */
    ap_rvputs(rc->r,
              "<requesterSubject>",
              apr_xml_quote_string(rc->r->pool, response->requester, 1),
              "</requesterSubject>", NULL);

    /* subject (if present) */
    if (response->subject != NULL) {
        ap_rvputs(rc->r,
                  "<subject>",
                  apr_xml_quote_string(rc->r->pool, response->subject, 1),
                  "</subject>", NULL);
    }

    /* authzSubject (if present) */
    if (response->authz_subject != NULL) {
        ap_rvputs(rc->r,
                  "<authzSubject>",
                  apr_xml_quote_string(rc->r->pool, response->authz_subject,
                                       1),
                  "</authzSubject>", NULL);
    }

    /* permittedAuthzSubjects (if present) */
    if (response->permitted_authz != NULL) {
        const char *authz;

        ap_rvputs(rc->r, "<permittedAuthzSubjects>", NULL);
        for (i = 0; i < response->permitted_authz->nelts; i++) {
            authz = APR_ARRAY_IDX(response->permitted_authz, i, const char *);
            ap_rvputs(rc->r, "<authzSubject>",
                      apr_xml_quote_string(rc->r->pool, authz, 1),
                      "</authzSubject>", NULL);
        }
        ap_rvputs(rc->r, "</permittedAuthzSubjects>", NULL);
    }

    /* requestedToken, don't need to quote */
    if (response->result != NULL) {
        ap_rvputs(rc->r,
                  "<requestedToken>",
                  response->result,
                  "</requestedToken>",
                  NULL);
        ap_rvputs(rc->r,
                  "<requestedTokenType>",
                  apr_xml_quote_string(rc->r->pool, response->result_type, 1),
                  "</requestedTokenType>", NULL);
    }

    if (response->login_cancel != NULL) {
        ap_rvputs(rc->r, "<loginCanceledToken>", response->login_cancel,
                  "</loginCanceledToken>", NULL);
    }

    /* appState, need to base64-encode */
    if (response->app_state != NULL) {
        char *out_state =
            apr_palloc(rc->r->pool,
                       apr_base64_encode_len(response->app_state_len));
        apr_base64_encode(out_state, response->app_state,
                          response->app_state_len);
        /*  don't need to quote */
        ap_rvputs(rc->r,
                  "<appState>", out_state , "</appState>",
                  NULL);
    }

    /* loginHistory (if present) */
    if (response->logins != NULL) {
        struct webauth_login *login;

        ap_rvputs(rc->r, "<loginHistory>", NULL);
        for (i = 0; i < response->logins->nelts; i++) {
            login = &APR_ARRAY_IDX(response->logins, i, struct webauth_login);
            ap_rvputs(rc->r, "<loginLocation", NULL);
            if (login->hostname != NULL)
                ap_rvputs(rc->r, " name=\"", login->hostname, "\"", NULL);
            if (login->timestamp != 0)
                ap_rprintf(rc->r, " time=\"%lu\"",
                           (unsigned long) login->timestamp);
            ap_rvputs(rc->r, ">", login->ip, "</loginLocation>", NULL);
        }
        ap_rvputs(rc->r, "</loginHistory>", NULL);
    }

    /* passwordExpires (if present) */
    if (response->password_expires > 0)
        ap_rprintf(rc->r, "<passwordExpires>%lu</passwordExpires>",
                   (unsigned long) response->password_expires);

    ap_rvputs(rc->r, "</requestTokenResponse>", NULL);
    ap_rflush(rc->r);

    return MWK_OK;
}


static enum mwk_status
handle_webkdcProxyTokenRequest(MWK_REQ_CTXT *rc, apr_xml_elem *e,
                               char **subject_out)
{
    apr_xml_elem *child;
    static const char *mwk_func = "handle_webkdcProxyTokenRequest";
    enum mwk_status ms;
    char *bsc_data = NULL;
    char *bpd_data = NULL;
    void *sc_data, *pd_data, *dpd_data, *tgt;
    const char *token_data;
    size_t sc_len, pd_len, dpd_len, tgt_len;
    int status;
    char *client_principal, *proxy_subject, *server_principal;
    char *check_principal;
    time_t tgt_expiration;
    struct webauth_krb5 *kc;
    struct webauth_token token;

    *subject_out = apr_pstrdup(rc->r->pool, "<unknown>");
    client_principal = NULL;
    ms = MWK_ERROR;

    /* walk through each child element in <requestTokenRequest> */
    for (child = e->first_child; child; child = child->next) {
        if (strcmp(child->name, "proxyData") == 0) {
            bpd_data = get_elem_text(rc, child, mwk_func);
            if (bpd_data == NULL)
                return MWK_ERROR;
        } else if (strcmp(child->name, "subjectCredential") == 0) {
            const char *at = get_attr_value(rc, child, "type",  1, mwk_func);
            if (at == NULL)
                return MWK_ERROR;

            if (strcmp(at, "krb5") != 0) {
                char *msg = apr_psprintf(rc->r->pool,
                                        "unknown <subjectCredential> type: %s",
                                         at);
                return set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg,
                                         mwk_func, true);
            }
            bsc_data = get_elem_text(rc, child, mwk_func);
            if (bsc_data == NULL)
                return MWK_ERROR;
        } else {
            unknown_element(rc, mwk_func, e->name, child->name);
            return MWK_ERROR;
        }
    }

    /* make sure we found proxyData */
    if (bpd_data == NULL) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "missing <proxyData>",
                                 mwk_func, true);
    }

    /* make sure we found subjectCredentials */
    if (bsc_data == NULL) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "missing <subjectCredential>",
                                 mwk_func, true);
    }

    /* Decode the base64 encoding. */
    sc_data = apr_palloc(rc->r->pool, apr_base64_decode_len(bsc_data));
    sc_len = apr_base64_decode(sc_data, bsc_data);
    pd_data = apr_palloc(rc->r->pool, apr_base64_decode_len(bpd_data));
    pd_len = apr_base64_decode(pd_data, bpd_data);

    /* Process the Kerberos authenticator and encrypted data. */
    kc = mwk_get_webauth_krb5_ctxt(rc->ctx, rc->r, mwk_func);
    /* mwk_get_webauth_krb5_ctxt already logged error */
    if (kc == NULL) {
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "server failure", mwk_func, false);
    }

    status = webauth_krb5_read_auth_data(rc->ctx, kc,
                                         sc_data,
                                         sc_len,
                                         rc->sconf->keytab_path,
                                         rc->sconf->keytab_principal,
                                         &server_principal,
                                         &client_principal,
                                         0,
                                         pd_data,
                                         pd_len,
                                         &dpd_data,
                                         &dpd_len);

    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->ctx, rc->r, status,
                                             "webauth_krb5_read_auth_data",
                                              NULL);
        set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg, mwk_func, true);
        goto cleanup;
    }
    proxy_subject = apr_pstrcat(rc->r->pool, "WEBKDC:", server_principal,
                                NULL);

    status = webauth_krb5_import_cred(rc->ctx, kc, dpd_data, dpd_len, NULL);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->ctx, rc->r, status,
                                              "webauth_krb5_import_cred",
                                              NULL);
        set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg, mwk_func, true);
        goto cleanup;
    }
    status = webauth_krb5_get_principal(rc->ctx, kc, &check_principal,
                                        WA_KRB5_CANON_NONE);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->ctx, rc->r, status,
                                              "webauth_krb5_get_principal",
                                              NULL);
        set_errorResponse(rc, WA_PEC_SERVER_FAILURE, msg, mwk_func, true);
        goto cleanup;
    }

    /*
     * Clients aren't allowed to forward a TGT for a different principal than
     * the authentication principal.
     */
    if (strcmp(client_principal, check_principal) != 0) {
        set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                          "authenticator and Kerberos TGT mismatch",
                          mwk_func, true);
        goto cleanup;
    }

    /* Check if the realm of the authenticated principal is permitted. */
    if (realm_permitted(rc, kc, mwk_func) != MWK_OK)
        goto cleanup;

    /* Get the subject and canonicalize the authentication identity. */
    if (get_subject(rc, kc, subject_out, mwk_func) != MWK_OK)
        goto cleanup;

    /* now export the tgt again, for sanity checking and to get
       expiration */
    status = webauth_krb5_export_cred(rc->ctx, kc, NULL, &tgt, &tgt_len,
                                      &tgt_expiration);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->ctx, rc->r, status,
                                              "webauth_krb5_export_cred",
                                              NULL);
        set_errorResponse(rc, WA_PEC_SERVER_FAILURE, msg, mwk_func, true);
        goto cleanup;
    }

    /* if ProxyTopkenLifetime is non-zero, use the min of it
       and the tgt, else just use the tgt  */
    if (rc->sconf->proxy_lifetime) {
        time_t pmax = time(NULL) + rc->sconf->proxy_lifetime;

        tgt_expiration = (tgt_expiration < pmax) ? tgt_expiration : pmax;
    }
    memset(&token, 0, sizeof(token));
    token.type = WA_TOKEN_WEBKDC_PROXY;
    token.token.webkdc_proxy.subject = *subject_out;
    token.token.webkdc_proxy.proxy_type = "krb5";
    token.token.webkdc_proxy.proxy_subject = proxy_subject;
    token.token.webkdc_proxy.data = tgt;
    token.token.webkdc_proxy.data_len = tgt_len;
    token.token.webkdc_proxy.expiration = tgt_expiration;

    /*
     * Get the initial factors for the token, or set to 'u' if
     * the factors array is unset
     */

    if (rc->sconf->kerberos_factors->nelts > 0) {
        char *p;
        p = apr_array_pstrcat(rc->r->pool, rc->sconf->kerberos_factors, ',');
        token.token.webkdc_proxy.initial_factors = p;
    } else {
        token.token.webkdc_proxy.initial_factors = "u";
    }

    ms = make_token(rc, &token, &token_data, mwk_func);
    if (ms != MWK_OK)
        goto cleanup;

    ap_rvputs(rc->r, "<webkdcProxyTokenResponse>", NULL);

    ap_rvputs(rc->r,
              "<webkdcProxyToken>",
              token_data,
              "</webkdcProxyToken>",
              NULL);

    /* subject */
    if (*subject_out != NULL) {
        ap_rvputs(rc->r,
                  "<subject>",
                  apr_xml_quote_string(rc->r->pool, *subject_out, 1),
                  "</subject>", NULL);
    }

    ap_rvputs(rc->r, "</webkdcProxyTokenResponse>", NULL);
    ap_rflush(rc->r);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, rc->r->server,
                 "mod_webkdc: event=webkdcProxyToken from=%s user=%s",
                 rc->r->useragent_ip,
                 *subject_out);
    ms = MWK_OK;

cleanup:
    return ms;
}


static enum mwk_status
handle_webkdcProxyTokenInfoRequest(MWK_REQ_CTXT *rc,
                                   apr_xml_elem *e,
                                   const char **subject_out)
{
    apr_xml_elem *child;
    static const char *mwk_func="handle_webkdcProxyTokenInfoRequest";
    enum mwk_status ms;
    struct webauth_token_webkdc_proxy pt;
    char *pt_data;

    pt_data = NULL;
    *subject_out = "<unknown>";

    /* walk through each child element in <requestTokenRequest> */
    for (child = e->first_child; child; child = child->next) {
        if (strcmp(child->name, "webkdcProxyToken") == 0) {
            pt_data = get_elem_text(rc, child, mwk_func);
            if (pt_data == NULL)
                return MWK_ERROR;
        } else {
            unknown_element(rc, mwk_func, e->name, child->name);
            return MWK_ERROR;
        }
    }

    /* make sure we found token */
    if (pt_data == NULL) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "missing <webkdcProxyToken>",
                                 mwk_func, true);
    }

    if (!parse_webkdc_proxy_token(rc, pt_data, &pt))
        return MWK_ERROR;

    ap_rvputs(rc->r, "<webkdcProxyTokenInfoResponse>", NULL);

    /* subject */
    ap_rvputs(rc->r,
             "<subject>",
             apr_xml_quote_string(rc->r->pool, pt.subject, 1),
             "</subject>", NULL);

    ap_rvputs(rc->r,
             "<proxyType>",
             apr_xml_quote_string(rc->r->pool, pt.proxy_type, 1),
             "</proxyType>", NULL);

    ap_rprintf(rc->r, "<creationTime>%d</creationTime>", (int)pt.creation);
    ap_rprintf(rc->r, "<expirationTime>%d</expirationTime>", (int)pt.expiration);

    ap_rvputs(rc->r, "</webkdcProxyTokenInfoResponse>", NULL);
    ap_rflush(rc->r);

    *subject_out = pt.subject;
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, rc->r->server,
                 "mod_webkdc: event=webkdcProxyTokenInfo from=%s user=%s",
                 rc->r->useragent_ip,
                 *subject_out);
    ms = MWK_OK;
    return ms;

}

static int
parse_request(MWK_REQ_CTXT *rc)
{
    int s;
    ssize_t num_read;
    char buff[8192];
    apr_xml_parser *xp;
    apr_xml_doc *xd;
    apr_status_t astatus;
    const char *mwk_func = "parse_request";

    xp = apr_xml_parser_create(rc->r->pool);
    if (xp == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webkdc: %s: "
                     "apr_xml_parser_create failed", mwk_func);
        set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                          "server failure", mwk_func, false);
        generate_errorResponse(rc);
        return OK;
    }

    s = ap_setup_client_block(rc->r, REQUEST_CHUNKED_DECHUNK);
    if (s!= OK)
        return s;

    astatus = APR_SUCCESS;
    num_read = 0;

    while (astatus == APR_SUCCESS &&
           ((num_read = ap_get_client_block(rc->r, buff, sizeof(buff))) > 0)) {
        astatus = apr_xml_parser_feed(xp, buff, num_read);
    }

    if (num_read == 0 && astatus == APR_SUCCESS)
        astatus = apr_xml_parser_done(xp, &xd);

    if ((num_read < 0) || astatus != APR_SUCCESS) {
        if (astatus != APR_SUCCESS) {
            char errbuff[1024] = "";
            apr_xml_parser_geterror(xp, errbuff, sizeof(errbuff));
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                         "mod_webkdc: %s: "
                         "apr_xml_parser_feed failed: %s (%d)",
                         mwk_func,
                         errbuff,
                         astatus);
            set_errorResponse(rc, WA_PEC_INVALID_REQUEST, errbuff,
                              mwk_func, false);
            generate_errorResponse(rc);
            return OK;
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                       "mod_webkdc: %s: ap_get_client_block error", mwk_func);
            set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                              "read error while parsing", mwk_func, false);
            generate_errorResponse(rc);
            return OK;
        }
    }

    if (strcmp(xd->root->name, "getTokensRequest") == 0) {
        const char *req, *sub;

        if (!handle_getTokensRequest(rc, xd->root, &req, &sub)) {
            generate_errorResponse(rc);
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, rc->r->server,
                         "mod_webkdc: event=getTokens from=%s "
                         "server=%s user=%s%s%s",
                         rc->r->useragent_ip,
                         req,
                         sub,
                         rc->error_code == 0 ? "" :
                         apr_psprintf(rc->r->pool,
                                      " errorCode=%d", rc->error_code),
                         rc->error_message == NULL ? "" :
                         apr_psprintf(rc->r->pool, " errorMessage=%s",
                                      log_escape(rc, rc->error_message))
                         );
        }
    } else if (strcmp(xd->root->name, "requestTokenRequest") == 0) {
        const char *req, *sub;

        if (!handle_requestTokenRequest(rc, xd->root, &req, &sub)) {
            generate_errorResponse(rc);
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, rc->r->server,
                         "mod_webkdc: event=requestToken from=%s "
                         "server=%s user=%s%s%s",
                         rc->r->useragent_ip,
                         req,
                         sub,
                         rc->error_code == 0 ? "" :
                         apr_psprintf(rc->r->pool,
                                      " errorCode=%d", rc->error_code),
                         rc->error_message == NULL ? "" :
                         apr_psprintf(rc->r->pool, " errorMessage=%s",
                                      log_escape(rc, rc->error_message))
                         );
        }
    } else if (strcmp(xd->root->name, "webkdcProxyTokenRequest") == 0) {
        char *sub;

        if (!handle_webkdcProxyTokenRequest(rc, xd->root, &sub)) {
            generate_errorResponse(rc);
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, rc->r->server,
                         "mod_webkdc: event=webkdcProxyToken from=%s "
                         "user=%s%s%s",
                         rc->r->useragent_ip,
                         sub,
                         rc->error_code == 0 ? "" :
                         apr_psprintf(rc->r->pool,
                                      " errorCode=%d", rc->error_code),
                         rc->error_message == NULL ? "" :
                         apr_psprintf(rc->r->pool, " errorMessage=%s",
                                      log_escape(rc, rc->error_message))
                         );
        }
    } else if (strcmp(xd->root->name, "webkdcProxyTokenInfoRequest") == 0) {
        const char *sub;

        if (!handle_webkdcProxyTokenInfoRequest(rc, xd->root, &sub)) {
            generate_errorResponse(rc);
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, rc->r->server,
                         "mod_webkdc: event=webkdcProxyTokenInfo from=%s "
                         "user=%s%s%s",
                         rc->r->useragent_ip,
                         sub,
                         rc->error_code == 0 ? "" :
                         apr_psprintf(rc->r->pool,
                                      " errorCode=%d", rc->error_code),
                         rc->error_message == NULL ? "" :
                         apr_psprintf(rc->r->pool, " errorMessage=%s",
                                      log_escape(rc, rc->error_message))
                         );
        }
    } else {
        char *m = apr_psprintf(rc->r->pool, "invalid command: %s",
                               xd->root->name);
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webkdc: %s: %s (from %s)", mwk_func, m,
                     rc->r->useragent_ip);
        set_errorResponse(rc, WA_PEC_INVALID_REQUEST, m, mwk_func, false);
        generate_errorResponse(rc);
        return OK;
    }
    return OK;
}

/* The content handler */
static int
handler_hook(request_rec *r)
{
    MWK_REQ_CTXT rc;
    int status;
    const char *req_content_type;
    struct webauth_webkdc_config config;

    /* Make sure that we weren't called inappropriately. */
    if (strcmp(r->handler, "webkdc"))
        return DECLINED;

    /* Initialize our request context. */
    memset(&rc, 0, sizeof(rc));
    rc.r = r;
    status = webauth_context_init_apr(&rc.ctx, r->pool);
    if (status != WA_ERR_NONE) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
                     "mod_webkdc: webauth_context_init failed: %s",
                     webauth_error_message(NULL, status));
        return DECLINED;
    }
    webauth_log_callback(rc.ctx, WA_LOG_TRACE,  mwk_log_trace,   r);
    webauth_log_callback(rc.ctx, WA_LOG_INFO,   mwk_log_info,    r);
    webauth_log_callback(rc.ctx, WA_LOG_NOTICE, mwk_log_notice,  r);
    webauth_log_callback(rc.ctx, WA_LOG_WARN,   mwk_log_warning, r);

    /* Set up the WebKDC configuration. */
    rc.sconf = ap_get_module_config(r->server->module_config, &webkdc_module);
    config.fast_armor_path  = rc.sconf->fast_armor_path;
    config.id_acl_path      = rc.sconf->identity_acl_path;
    config.keytab_path      = rc.sconf->keytab_path;
    config.principal        = rc.sconf->keytab_principal;
    config.proxy_lifetime   = rc.sconf->proxy_lifetime;
    config.login_time_limit = rc.sconf->login_time_limit;
    config.permitted_realms = rc.sconf->permitted_realms;
    config.local_realms     = rc.sconf->local_realms;
    status = webauth_webkdc_config(rc.ctx, &config);
    if (status != WA_ERR_NONE) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
                     "mod_webkdc: webauth_webkdc_config failed: %s",
                     webauth_error_message(rc.ctx, status));
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Set up the user information service configuration. */
    if (rc.sconf->userinfo_config != NULL) {
        struct webauth_user_config *user = rc.sconf->userinfo_config;

        user->identity       = rc.sconf->userinfo_principal;
        user->timeout        = rc.sconf->userinfo_timeout;
        user->ignore_failure = rc.sconf->userinfo_ignore_fail;
        user->json           = rc.sconf->userinfo_json;
        user->keytab         = rc.sconf->keytab_path;
        user->principal      = rc.sconf->keytab_principal;
        status = webauth_user_config(rc.ctx, user);
        if (status != WA_ERR_NONE) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
                         "mod_webkdc: webauth_user_config failed: %s",
                         webauth_error_message(rc.ctx, status));
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* Ensure we can load the keyring. */
    if (!ensure_keyring_loaded(&rc))
        return HTTP_INTERNAL_SERVER_ERROR;

    /* Ensure the client sent POST with the right content type. */
    if (r->method_number != M_POST)
        return HTTP_METHOD_NOT_ALLOWED;
    req_content_type = apr_table_get(r->headers_in, "content-type");
    if (!req_content_type || strcmp(req_content_type, "text/xml") != 0)
        return HTTP_BAD_REQUEST;

    /* Our response will also be text/xml. */
    ap_set_content_type(r, "text/xml");

    /* All the real work happens in parse_request. */
    return parse_request(&rc);
}


/*
 * called after config has been loaded in parent process
 */
static int
mod_webkdc_init(apr_pool_t *pconf, apr_pool_t *plog UNUSED,
                apr_pool_t *ptemp UNUSED, server_rec *s)
{
    struct config *sconf;
    server_rec *scheck;

    sconf = ap_get_module_config(s->module_config, &webkdc_module);

    if (sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "mod_webkdc: initializing");

    for (scheck=s; scheck; scheck=scheck->next) {
        webkdc_config_init(scheck, sconf, pconf);
    }

    ap_add_version_component(pconf, "WebKDC/" VERSION);

    if (sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "mod_webkdc: initialized (%s) (%s)", VERSION,
                     PACKAGE_BUILD_INFO);

    return OK;
}

/*
 * called once per-child
 */
static void
mod_webkdc_child_init(apr_pool_t *p UNUSED, server_rec *s)
{
    /* initialize mutexes */
    mwk_init_mutexes(s);
}

static void
register_hooks(apr_pool_t *p UNUSED)
{
    ap_hook_post_config(mod_webkdc_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(mod_webkdc_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(handler_hook, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA webkdc_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    webkdc_config_create,  /* create per-server config structures */
    webkdc_config_merge,   /* merge  per-server config structures */
    webkdc_cmds,           /* table of config file commands       */
    register_hooks         /* register hooks                      */
};
