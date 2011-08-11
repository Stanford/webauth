/*
 * Core Apache WebKDC module code.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2004, 2005, 2006, 2008, 2009, 2010, 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <modules/mod-config.h>
#include <portable/stdbool.h>

#include <apr_base64.h>
#include <apr_lib.h>
#include <apr_pools.h>
#include <apr_tables.h>
#include <apr_strings.h>
#include <apr_xml.h>
#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_protocol.h>

#include <modules/webkdc/mod_webkdc.h>
#include <util/macros.h>
#include <webauth/basic.h>
#include <webauth/keys.h>
#include <webauth/tokens.h>
#include <webauth/webkdc.h>


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
        if (rc->sconf->ring == NULL)
            return set_errorResponse(rc, WA_PEC_SERVER_FAILURE, "no keyring",
                                     mwk_func, true);
        status = webauth_token_decode(rc->ctx, WA_TOKEN_WEBKDC_SERVICE, token,
                                      rc->sconf->ring, &data);
        if (status != WA_ERR_NONE) {
            mwk_log_webauth_error(rc->r->server, status, NULL, mwk_func,
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
        WEBAUTH_KRB5_CTXT *ctxt = mwk_get_webauth_krb5_ctxt(rc->r, mwk_func);
        /* mwk_get_webauth_krb5_ctxt already logged error */
        if (ctxt == NULL) {
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

        status = webauth_krb5_rd_req(ctxt, bin_req, blen,
                                     rc->sconf->keytab_path,
                                     rc->sconf->keytab_principal,
                                     &client_principal, 0);

        if (status != WA_ERR_NONE) {
            char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                                  "webauth_krb5_rd_req", NULL);
            set_errorResponse(rc, WA_PEC_REQUESTER_KRB5_CRED_INVALID, msg,
                              mwk_func, true);
            webauth_krb5_free(ctxt);
            return MWK_ERROR;
        }
        webauth_krb5_free(ctxt);
        req_cred->subject = apr_pstrcat(rc->r->pool, "krb5:", client_principal,
                                        NULL);
        free(client_principal);

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

    if (rc->sconf->ring == NULL)
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE, "no keyring",
                                 mwk_func, true);
    status = webauth_token_decode(rc->ctx, WA_TOKEN_WEBKDC_PROXY, token,
                                  rc->sconf->ring, &data);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r->server, status, NULL, mwk_func,
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

    if (rc->sconf->ring == NULL)
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE, "no keyring",
                                 mwk_func, true);
    status = webauth_token_decode(rc->ctx, WA_TOKEN_LOGIN, token,
                                  rc->sconf->ring, &data);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r->server, status, NULL, mwk_func,
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

    if (rc->sconf->ring == NULL)
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "no keyring", mwk_func, true);
    status = webauth_token_encode(rc->ctx, data, rc->sconf->ring, token);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r->server, status, NULL, mwk_func,
                              "webauth_token_create", NULL);
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "token create failed", mwk_func, false);
    }
    return MWK_OK;
}

static enum mwk_status
make_token_raw(MWK_REQ_CTXT *rc, struct webauth_token *data,
               const void **token, size_t *length, const char *mwk_func)
{
    int status;
    WEBAUTH_KEYRING *ring;

    if (rc->sconf->ring == NULL)
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "no keyring", mwk_func, true);
    ring = rc->sconf->ring;
    status = webauth_token_encode_raw(rc->ctx, data, ring, token, length);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r->server, status, NULL, mwk_func,
                              "webauth_token_create", NULL);
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "token create failed", mwk_func, false);
    }
    return MWK_OK;
}

/* FIXME: The key argument here is an ugly hack. */
static enum mwk_status
make_token_with_key(MWK_REQ_CTXT *rc, const void *key, size_t key_len,
                    struct webauth_token *data, const char **token,
                    const char *mwk_func)
{
    int status;
    WEBAUTH_KEYRING *ring;
    WEBAUTH_KEY wkey;

    wkey.type = WA_AES_KEY;
    wkey.length = key_len;
    wkey.data = (void *) key;
    status = webauth_keyring_from_key(rc->ctx, &wkey, &ring);
    if (status != WA_ERR_NONE)
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "cannot create keyring from key",
                                 mwk_func, true);
    status = webauth_token_encode(rc->ctx, data, ring, token);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r->server, status, NULL, mwk_func,
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
    static const char *mwk_func="create_service_token_from_req";
    char session_key[WA_AES_128];
    int status;
    size_t len;
    enum mwk_status ms;
    time_t expiration;
    struct webauth_token token;

    ms = MWK_ERROR;

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

    status = webauth_random_key(session_key, sizeof(session_key));

    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r->server, status, NULL, mwk_func,
                              "webauth_random_key", NULL);
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "can't generate session key", mwk_func,
                                 false);
    }

    memset(&token, 0, sizeof(token));
    expiration = time(NULL) + rc->sconf->service_lifetime;
    token.type = WA_TOKEN_WEBKDC_SERVICE;
    token.token.webkdc_service.subject = req_cred->subject;
    token.token.webkdc_service.session_key = session_key;
    token.token.webkdc_service.session_key_len = sizeof(session_key);
    token.token.webkdc_service.expiration = expiration;
    ms = make_token(rc, &token, &rtoken->token_data, mwk_func);

    if (!ms)
        return MWK_ERROR;

    rtoken->expires = apr_psprintf(rc->r->pool, "%lu",
                                   (unsigned long) expiration);

    len = sizeof(session_key);
    rtoken->session_key = apr_palloc(rc->r->pool, apr_base64_encode_len(len));
    apr_base64_encode(rtoken->session_key, session_key, len);

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
             char **sad,
             size_t *sad_len,
             const char *mwk_func)
{
    WEBAUTH_KRB5_CTXT *ctxt;
    int status;
    const char *server_principal;
    char *temp_sad;
    enum mwk_status ms;

    ctxt = mwk_get_webauth_krb5_ctxt(rc->r, mwk_func);
    if (ctxt == NULL) {
        /* mwk_get_webauth_krb5_ctxt already logged error */
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                      "server failure (webauth_krb5_new)",
                                      mwk_func, false);
    }

    status = webauth_krb5_init_via_cred(ctxt, sub_pt->data, sub_pt->data_len,
                                        NULL);

    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r,
                                              status, ctxt,
                                              "webauth_krb5_export_ticket",
                                              NULL);
        webauth_krb5_free(ctxt);
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

    status = webauth_krb5_mk_req(ctxt, server_principal, &temp_sad, sad_len);

    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                              "webauth_krb5_mk_req", NULL);
        /* FIXME: probably need to examine errors a little more closely
         *        to determine if we should return a proxy-token error
         *        or a server-failure.
         */
        set_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID, msg, mwk_func, true);
        ms = MWK_ERROR;
    } else {
        *sad = apr_palloc(rc->r->pool, *sad_len);
        memcpy(*sad,  temp_sad, *sad_len);
        free(temp_sad);
        ms = MWK_OK;
    }

    webauth_krb5_free(ctxt);
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
    char *sad;

    ms = MWK_ERROR;

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
create_proxy_token_from_req(MWK_REQ_CTXT *rc,
                               const char *proxy_type,
                               MWK_REQUESTER_CREDENTIAL *req_cred,
                               MWK_SUBJECT_CREDENTIAL *sub_cred,
                               MWK_RETURNED_TOKEN *rtoken)
{
    static const char *mwk_func = "create_proxy_token_from_req";
    size_t wkdc_len;
    enum mwk_status ms;
    struct webauth_token_webkdc_proxy *sub_pt;
    struct webauth_token pt, token;
    const void *wkdc_token;

    ms = MWK_ERROR;

    /* make sure proxy_type is not NULL */
    if (proxy_type == NULL) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "proxy type is NULL",
                                 mwk_func, true);
    }

    /* only create proxy tokens from service creds */
    if (strcmp(req_cred->type, "service") != 0) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "can only create proxy-tokens with "
                                 "<requesterCredential> of type service",
                                 mwk_func, true);
    }

    /* make sure we have a subject cred with a type='proxy' */
    if (strcmp(sub_cred->type, "proxy") != 0) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "can only create proxy-tokens with "
                                 "<subjectCredential> of type proxy",
                                 mwk_func, true);
    }

    /* check access */
    if (!mwk_has_proxy_access(rc, req_cred->subject, proxy_type)) {
        return set_errorResponse(rc, WA_PEC_UNAUTHORIZED,
                                 "not authorized to get a proxy token",
                                 mwk_func, true);
    }

    /* make sure we are creating a proxy-token that has
       the same type as the proxy-token we are using to create it */
    sub_pt = find_proxy_token(rc, sub_cred, proxy_type, mwk_func, 1);
    if (sub_pt == NULL)
        return MWK_ERROR;

    /* check access again */
    if (!mwk_can_use_proxy_token(rc, req_cred->subject,
                                 sub_pt->proxy_subject)) {
        return set_errorResponse(rc, WA_PEC_UNAUTHORIZED,
                                 "not authorized to use proxy token",
                                 mwk_func, true);
    }

    /* create the webkdc-proxy-token first, using existing proxy-token */
    memset(&pt, 0, sizeof(pt));
    pt.type = WA_TOKEN_WEBKDC_PROXY;
    pt.token.webkdc_proxy = *sub_pt;
    pt.token.webkdc_proxy.creation = 0;
    ms = make_token_raw(rc, &pt, &wkdc_token, &wkdc_len, mwk_func);
    if (!ms)
        return MWK_ERROR;

    /* now create the proxy-token */
    memset(&token, 0, sizeof(token));
    token.type = WA_TOKEN_PROXY;
    token.token.proxy.subject = sub_pt->subject;
    token.token.proxy.type = sub_pt->proxy_type;
    token.token.proxy.webkdc_proxy = wkdc_token;
    token.token.proxy.webkdc_proxy_len = wkdc_len;
    token.token.proxy.expiration = sub_pt->expiration;
    if (sub_pt->initial_factors != NULL)
        token.token.proxy.initial_factors = sub_pt->initial_factors;
    if (sub_pt->loa > 0)
        token.token.proxy.loa = sub_pt->loa;

    /* FIXME: Hardcoded for now, needs to come from the proxy token origin. */
    token.token.proxy.session_factors = "u";

    ms = make_token_with_key(rc, req_cred->u.st.session_key,
                             req_cred->u.st.session_key_len, &token,
                             &rtoken->token_data, mwk_func);

    rtoken->subject = sub_pt->subject;
    rtoken->info =
        apr_pstrcat(rc->r->pool, " type=proxy pt=", proxy_type, NULL);

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
    WEBAUTH_KRB5_CTXT *ctxt;
    struct webauth_token_webkdc_proxy *sub_pt;
    struct webauth_token token;
    char *ticket;
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
    ctxt = mwk_get_webauth_krb5_ctxt(rc->r, mwk_func);
    if (ctxt == NULL) {
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                      "server failure", mwk_func, false);
    }

    status = webauth_krb5_init_via_cred(ctxt, sub_pt->data, sub_pt->data_len,
                                        NULL);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r,
                                              status, ctxt,
                                              "webauth_krb5_init_via_cred",
                                              NULL);
        webauth_krb5_free(ctxt);
        /* FIXME: probably need to examine errors a little more closely
         *        to determine if we should return a proxy-token error
         *        or a server-failure.
         */
        return set_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID, msg,
                                 mwk_func, true);
    }

    /* now try and export a ticket */
    status = webauth_krb5_export_ticket(ctxt,
                                        sp,
                                        &ticket,
                                        &ticket_len,
                                        &ticket_expiration);

    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r,
                                              status, ctxt,
                                              "webauth_krb5_export_ticket",
                                              NULL);
        webauth_krb5_free(ctxt);
        return set_errorResponse(rc, WA_PEC_GET_CRED_FAILURE,
                                 msg, mwk_func, true);
    }

    webauth_krb5_free(ctxt);

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

    free(ticket);
    return ms;
}

/*
 * parse a <requestToken> from a POST, which should be base64-encoded.
 * return 1 on success, 0 on error.
 * logs all errors and generates errorResponse if need be.
 */
static enum mwk_status
parse_request_token(MWK_REQ_CTXT *rc,
                    char *token,
                    struct webauth_token_webkdc_service *st,
                    struct webauth_token_request **rt)
{
    int status;
    struct webauth_token *data;
    WEBAUTH_KEY key;
    WEBAUTH_KEYRING *ring;
    time_t expiration;
    static const char *mwk_func = "parse_xml_request_token";

    if (token == NULL) {
        return set_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID,
                                 "request token is NULL", mwk_func, true);
    }

    /* FIXME: This is a horrible hack. */
    key.type = WA_AES_KEY;
    key.length = st->session_key_len;
    key.data = (void *) st->session_key;
    status = webauth_keyring_from_key(rc->ctx, &key, &ring);
    if (status != WA_ERR_NONE)
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "cannot generate keyring", mwk_func, true);
    status = webauth_token_decode(rc->ctx, WA_TOKEN_REQUEST, token, ring,
                                  &data);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r->server, status, NULL,
                              "parse_xml_request_token",
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
    if (expiration < time(NULL))
        set_errorResponse(rc, WA_PEC_REQUEST_TOKEN_STALE,
                          "request token was stale", mwk_func, false);
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
    struct webauth_token_request *req_token;
    MWK_REQUESTER_CREDENTIAL req_cred;
    MWK_SUBJECT_CREDENTIAL sub_cred;
    int req_cred_parsed = 0;
    int sub_cred_parsed = 0;
    size_t num_tokens, i;

    MWK_RETURNED_TOKEN rtokens[MAX_TOKENS_RETURNED];

    *subject_out = "<unknown>";
    *req_subject_out = "<unkknown>";
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
        } else if (strcmp(tt, "proxy") == 0) {
            apr_xml_elem *proxy_type;
            const char *pt;

            proxy_type = get_element(rc, token, "proxyType", 1, mwk_func);

            if (proxy_type == NULL)
                return MWK_ERROR;

            pt = get_elem_text(rc, proxy_type, mwk_func);
            if (pt == NULL)
                return MWK_ERROR;

            if (!create_proxy_token_from_req(rc, pt, &req_cred, &sub_cred,
                                             &rtokens[num_tokens])) {
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
                     rc->r->connection->remote_ip,
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
realm_permitted(MWK_REQ_CTXT *rc, WEBAUTH_KRB5_CTXT *ctxt,
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
    status = webauth_krb5_get_realm(ctxt, &realm);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                             "webauth_krb5_get_realm", NULL);
        set_errorResponse(rc, WA_PEC_SERVER_FAILURE, msg, mwk_func, true);
        return MWK_ERROR;
    }

    /*
     * We assume that all realms listed in the configuration are already
     * escaped, as is the realm parameter.
     */
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
        free(realm);
        return MWK_ERROR;
    }
    free(realm);
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
get_subject(MWK_REQ_CTXT *rc, WEBAUTH_KRB5_CTXT *ctxt,
            const char **subject_out, const char *mwk_func)
{
    char *subject;
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
            status = webauth_krb5_get_realm(ctxt, &realm);
            if (status != WA_ERR_NONE) {
                char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
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
            free(realm);
        }
    }

    /*
     * We now know the canonicalization method we're using, so we can retrieve
     * the principal from the context.
     */
    status = webauth_krb5_get_principal(ctxt, &subject, canonicalize);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                             "webauth_krb5_get_principal",
                                              NULL);
        set_errorResponse(rc, WA_PEC_SERVER_FAILURE, msg, mwk_func, true);
        return MWK_ERROR;
    }
    *subject_out = apr_pstrdup(rc->r->pool, subject);
    free(subject);
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
                    struct webauth_webkdc_login_request *request)
{
    static const char *mwk_func = "parse_service_token";
    int status;
    struct webauth_token *data;
    const char *at = get_attr_value(rc, e, "type", 1, mwk_func);
    char *msg, *token;

    if (rc->sconf->ring == NULL)
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
        mwk_log_webauth_error(rc->r->server, status, NULL, mwk_func,
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
    request->service = &data->token.webkdc_service;
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
    struct webauth_token *token;
    struct webauth_token_webkdc_proxy *wkproxy;

    if (request->creds == NULL)
        request->creds = apr_array_make(rc->r->pool, 2,
                                        sizeof(struct webauth_token *));

    /*
     * Just quietly ignore invalid webkdc-proxy tokens for right now.
     *
     * FIXME: Restore a facility for telling WebLogin to discard uninteresting
     * webkdc-proxy tokens.
     *
     * FIXME: We're calling functions that get generic tokens and collapse
     * them into the appropriate type, and then allocating a generic token and
     * copying it back.  This is silly.  Restructure all this code.
     */
    for (child = e->first_child; child != NULL; child = child->next) {
        if (strcmp(child->name, "proxyToken") == 0) {
            data = get_elem_text(rc, child, mwk_func);
            if (data == NULL)
                return MWK_ERROR;
            token = apr_pcalloc(rc->r->pool, sizeof(struct webauth_token));
            token->type = WA_TOKEN_WEBKDC_PROXY;
            wkproxy = &token->token.webkdc_proxy;
            if (!parse_webkdc_proxy_token(rc, data, wkproxy))
                continue;
            for (a = child->attr; a != NULL; a = a->next)
                if (strcmp(a->name, "source") == 0) {
                    wkproxy->session_factors = a->value;
                    break;
                }
            APR_ARRAY_PUSH(request->creds, struct webauth_token *) = token;
        } else if (strcmp(child->name, "loginToken") == 0) {
            data = get_elem_text(rc, child, mwk_func);
            if (data == NULL)
                return MWK_ERROR;
            token = apr_pcalloc(rc->r->pool, sizeof(struct webauth_token));
            token->type = WA_TOKEN_LOGIN;
            if (!parse_login_token(rc, data, &token->token.login))
                return MWK_ERROR;
            APR_ARRAY_PUSH(request->creds, struct webauth_token *) = token;
        } else {
            unknown_element(rc, mwk_func, e->name, child->name);
            return MWK_ERROR;
        }
    }
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
print_xml_array(MWK_REQ_CTXT *rc, const char *tag, apr_array_header_t *array)
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
    char *request_token = NULL;
    int i, status;
    const char *req_token_info;
    struct webauth_webkdc_login_request request;
    struct webauth_webkdc_login_response *response;

    /*
     * FIXME: These should be set to NULL, not <unknown>.  Chase down all the
     * places we assume they aren't NULL.
     */
    *subject_out = "<unknown>";
    *req_subject_out = "<unkknown>";

    req_token_info = "";
    memset(&request, 0, sizeof(request));

    /* walk through each child element in <requestTokenRequest> */
    for (child = e->first_child; child; child = child->next) {
        if (strcmp(child->name, "requesterCredential") == 0) {
            if (!parse_service_token(rc, child, &request))
                return MWK_ERROR;
        } else if (strcmp(child->name, "subjectCredential") == 0) {
            if (!parse_subject_credentials(rc, child, &request))
                return MWK_ERROR;
        } else if (strcmp(child->name, "requestToken") == 0) {
            request_token = get_elem_text(rc, child, mwk_func);
            if (request_token == NULL)
                return MWK_ERROR;
        } else if (strcmp(child->name, "requestInfo") == 0) {
            if (!parse_requestInfo(rc, child, &request))
                return MWK_ERROR;
        } else {
            unknown_element(rc, mwk_func, e->name, child->name);
            return MWK_ERROR;
        }
    }

    /* make sure we found requesterCredential */
    if (request.service == NULL) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "missing <requesterCredential>",
                                 mwk_func, true);
    }
    if (request.service != NULL)
        *req_subject_out = request.service->subject;

    /*
     * Make sure we found <subjectCredential>.  Note that the array may be
     * legitimately empty if the user has no proxy credentials and it's their
     * first visit to WebLogin.
     */
    if (request.creds == NULL)
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "missing <subjectCredential>",
                                 mwk_func, true);

    /* make sure we found requestToken */
    if (request_token == NULL) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "missing <requestToken>",
                                 mwk_func, true);
    }
    if (!parse_request_token(rc, request_token, request.service,
                             &request.request))
        return MWK_ERROR;

    /*
     * Based on the type of token requested, check that the requesting WAS is
     * permitted to get that type of token.
     */
    if (strcmp(request.request->type, "id") == 0) {
        if (!mwk_has_id_access(rc, request.service->subject)) {
            return set_errorResponse(rc, WA_PEC_UNAUTHORIZED,
                                     "not authorized to get an id token",
                                     mwk_func, true);
        }
    } else if (strcmp(request.request->type, "proxy") == 0) {
        if (!mwk_has_proxy_access(rc, request.service->subject,
                                  request.request->proxy_type)) {
            return set_errorResponse(rc, WA_PEC_UNAUTHORIZED,
                                 "not authorized to get a proxy token",
                                 mwk_func, true);
        }
    }

    /*
     * Call into libwebauth to process the login information.  This will take
     * the accumulated data in the request and attempt to fulfill it.  On an
     * internal error, this function will return a status other than
     * WA_ERR_NONE.  Otherwise, it may set the login_error and login_message
     * in the response.  We handle that below when we generate the XML
     * response.
     */
    status = webauth_webkdc_login(rc->ctx, &request, &response,
                                  rc->sconf->ring);
    if (status != WA_ERR_NONE)
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 webauth_error_message(rc->ctx, status),
                                 mwk_func, true);

    /* Accumulate logging information about what we were asked to do. */
    if (strcmp(request.request->type, "id") == 0)
        req_token_info = apr_pstrcat(rc->r->pool, " sa=", request.request->auth,
                                     NULL);
    else if (strcmp(request.request->type, "proxy") == 0)
        req_token_info = apr_pstrcat(rc->r->pool, " pt=",
                                     request.request->proxy_type, NULL);
    if (response->subject != NULL)
        *subject_out = response->subject;

    /*
     * If we saw an error other than proxy token required, abort and send the
     * error message.
     */
    if (response->login_error != 0
        && response->login_error != WA_PEC_PROXY_TOKEN_REQUIRED
        && response->login_error != WA_PEC_MULTIFACTOR_REQUIRED
        && response->login_error != WA_PEC_MULTIFACTOR_UNAVAILABLE
        && response->login_error != WA_PEC_LOA_UNAVAILABLE)
        return set_errorResponse(rc, response->login_error,
                                 response->login_message, mwk_func, true);

    /* Send the XML response. */
    ap_rvputs(rc->r, "<requestTokenResponse>", NULL);

    if (response->login_error != 0) {
        ap_rprintf(rc->r, "<loginErrorCode>%d</loginErrorCode>",
                   response->login_error);
        ap_rprintf(rc->r, "<loginErrorMessage>%s</loginErrorMessage>",
                   apr_xml_quote_string(rc->r->pool, response->login_message,
                                        false));
    }

    if (response->login_error == WA_PEC_MULTIFACTOR_REQUIRED) {
        ap_rvputs(rc->r, "<multifactorRequired>", NULL);
        print_xml_array(rc, "factor", response->factors_wanted);
        print_xml_array(rc, "configuredFactor", response->factors_configured);
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
    /* put out return-url */
    ap_rvputs(rc->r,"<returnUrl>",
              apr_xml_quote_string(rc->r->pool, response->return_url, 1),
              "</returnUrl>", NULL);

    /* requesterSubject */
    ap_rvputs(rc->r,
              "<requesterSubject>",
              apr_xml_quote_string(rc->r->pool, response->requester, 1),
              "</requesterSubject>", NULL);

    /* subject */
    if (response->subject != NULL) {
        ap_rvputs(rc->r,
                  "<subject>",
                  apr_xml_quote_string(rc->r->pool, response->subject, 1),
                  "</subject>", NULL);
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
            ap_rvputs(rc->r, "<loginLocation ip=\"", login->ip, "\"", NULL);
            if (login->timestamp != 0)
                ap_rprintf(rc->r, "time=\"%lu\"",
                           (unsigned long) login->timestamp);
            ap_rvputs(rc->r, ">", login->hostname, "</loginLocation>", NULL);
        }
        ap_rvputs(rc->r, "</loginHistory>", NULL);
    }

    /* passwordExpires (if present) */
    if (response->password_expires > 0)
        ap_rprintf(rc->r, "<passwordExpires>%lu</passwordExpires>",
                   (unsigned long) response->password_expires);

    ap_rvputs(rc->r, "</requestTokenResponse>", NULL);
    ap_rflush(rc->r);
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, rc->r->server,
                 "mod_webkdc: event=requestToken from=%s clientIp=%s "
                 "server=%s user=%s rtt=%s%s%s%s%s",
                 rc->r->connection->remote_ip,
                 (request.remote_ip == NULL ? "" : request.remote_ip),
                 response->requester,
                 (response->subject == NULL ? "<unknown>" : response->subject),
                 request.request->type,
                 req_token_info,
                 (request.request->options == NULL
                  || *request.request->options == '\0') ? "" :
                 apr_psprintf(rc->r->pool, " ro=%s", request.request->options),
                 apr_psprintf(rc->r->pool, " lec=%d", response->login_error),
                 response->login_message == NULL ? "" :
                 apr_psprintf(rc->r->pool, " lem=%s",
                              log_escape(rc, response->login_message))
                 );

    return MWK_OK;
}


static enum mwk_status
handle_webkdcProxyTokenRequest(MWK_REQ_CTXT *rc, apr_xml_elem *e,
                               const char **subject_out)
{
    apr_xml_elem *child;
    static const char *mwk_func = "handle_webkdcProxyTokenRequest";
    enum mwk_status ms;
    char *sc_data, *pd_data;
    char *dpd_data;
    const char *token_data;
    char *tgt;
    size_t sc_blen, sc_len, pd_blen, pd_len, dpd_len, tgt_len;
    int status;
    char *client_principal, *proxy_subject, *server_principal;
    char *check_principal;
    time_t tgt_expiration;
    WEBAUTH_KRB5_CTXT *ctxt;
    struct webauth_token token;

    *subject_out = "<unknown>";
    sc_data = NULL;
    pd_data = NULL;

    client_principal = NULL;
    ctxt = NULL;
    ms = MWK_ERROR;

    /* walk through each child element in <requestTokenRequest> */
    for (child = e->first_child; child; child = child->next) {
        if (strcmp(child->name, "proxyData") == 0) {
            pd_data = get_elem_text(rc, child, mwk_func);
            if (pd_data == NULL)
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
            sc_data = get_elem_text(rc, child, mwk_func);
            if (sc_data == NULL)
                return MWK_ERROR;
        } else {
            unknown_element(rc, mwk_func, e->name, child->name);
            return MWK_ERROR;
        }
    }

    /* make sure we found proxyData */
    if (pd_data == NULL) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "missing <proxyData>",
                                 mwk_func, true);
    }

    /* make sure we found subjectCredentials */
    if (sc_data == NULL) {
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                 "missing <subjectCredential>",
                                 mwk_func, true);
    }

    sc_blen = strlen(sc_data);
    status = webauth_base64_decode(sc_data, sc_blen,
                                   sc_data, &sc_len,
                                   sc_blen);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                              "webauth_base64_decode",
                                              "subjectCredential");
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg,
                                 mwk_func, true);
    }

    pd_blen = strlen(pd_data);
    status = webauth_base64_decode(pd_data, pd_blen,
                                   pd_data, &pd_len,
                                   pd_blen);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                        "webauth__base64_decode", "proxyData");
        return set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg,
                                 mwk_func, true);
    }

    ctxt = mwk_get_webauth_krb5_ctxt(rc->r, mwk_func);
    /* mwk_get_webauth_krb5_ctxt already logged error */
    if (ctxt == NULL) {
        return set_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                                 "server failure", mwk_func, false);
    }

    status = webauth_krb5_rd_req_with_data(ctxt,
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
        char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                             "webauth__krb5_rd_req_with_data",
                                              NULL);
        set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg, mwk_func, true);
        goto cleanup;
    }

    proxy_subject = apr_pstrcat(rc->r->pool, "WEBKDC:",
                                server_principal, NULL);
    free(server_principal);

    status = webauth_krb5_init_via_cred(ctxt, dpd_data, dpd_len, NULL);
    free(dpd_data);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                              "webauth_krb5_init_via_cred",
                                              NULL);
        set_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg, mwk_func, true);
        free(client_principal);
        goto cleanup;
    }
    status = webauth_krb5_get_principal(ctxt, &check_principal,
                                        WA_KRB5_CANON_NONE);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                              "webauth_krb5_get_principal",
                                              NULL);
        set_errorResponse(rc, WA_PEC_SERVER_FAILURE, msg, mwk_func, true);
        free(client_principal);
        goto cleanup;
    }

    /*
     * Clients aren't allowed to forward a TGT for a different principal than
     * the authentication principal.
     */
    if (strcmp(client_principal, check_principal) != 0) {
        free(client_principal);
        free(check_principal);
        set_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                          "authenticator and Kerberos TGT mismatch",
                          mwk_func, true);
        goto cleanup;
    }
    free(client_principal);
    free(check_principal);

    /* Check if the realm of the authenticated principal is permitted. */
    if (realm_permitted(rc, ctxt, mwk_func) != MWK_OK)
        goto cleanup;

    /* Get the subject and canonicalize the authentication identity. */
    if (get_subject(rc, ctxt, subject_out, mwk_func) != MWK_OK)
        goto cleanup;

    /* now export the tgt again, for sanity checking and to get
       expiration */
    status = webauth_krb5_export_tgt(ctxt, &tgt, &tgt_len, &tgt_expiration);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                              "webauth_krb5_export_tgt",
                                              NULL);
        set_errorResponse(rc, WA_PEC_SERVER_FAILURE, msg, mwk_func, true);
        goto cleanup;
    } else {
        char *new_tgt = apr_palloc(rc->r->pool, tgt_len);
        memcpy(new_tgt, tgt, tgt_len);
        free(tgt);
        tgt = new_tgt;
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
                 rc->r->connection->remote_ip,
                 *subject_out);
    ms = MWK_OK;

 cleanup:

    if (ctxt != NULL)
        webauth_krb5_free(ctxt);

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
    ms = MWK_ERROR;

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
                 rc->r->connection->remote_ip,
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
                         rc->r->connection->remote_ip,
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
                         rc->r->connection->remote_ip,
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
        const char *sub;

        if (!handle_webkdcProxyTokenRequest(rc, xd->root, &sub)) {
            generate_errorResponse(rc);
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, rc->r->server,
                         "mod_webkdc: event=webkdcProxyToken from=%s "
                         "user=%s%s%s",
                         rc->r->connection->remote_ip,
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
                         rc->r->connection->remote_ip,
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
                     rc->r->connection->remote_ip);
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

    memset(&rc, 0, sizeof(rc));
    status = webauth_context_init_apr(&rc.ctx, r->pool);
    if (status != WA_ERR_NONE) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
                     "mod_webkdc: webauth_context_init failed: %s",
                     webauth_error_message(NULL, status));
        return DECLINED;
    }

    rc.r = r;
    rc.sconf = ap_get_module_config(r->server->module_config, &webkdc_module);
    config.keytab_path = rc.sconf->keytab_path;
    config.principal = rc.sconf->keytab_principal;
    config.proxy_lifetime = rc.sconf->proxy_lifetime;
    config.permitted_realms = rc.sconf->permitted_realms;
    config.local_realms = rc.sconf->local_realms;
    status = webauth_webkdc_config(rc.ctx, &config);
    if (status != WA_ERR_NONE) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
                     "mod_webkdc: webauth_webkdc_config failed: %s",
                     webauth_error_message(rc.ctx, status));
        return DECLINED;
    }
    if (rc.sconf->userinfo_config != NULL) {
        rc.sconf->userinfo_config->identity = rc.sconf->userinfo_principal;
        rc.sconf->userinfo_config->keytab = rc.sconf->keytab_path;
        rc.sconf->userinfo_config->principal = rc.sconf->keytab_principal;
        status = webauth_user_config(rc.ctx, rc.sconf->userinfo_config);
        if (status != WA_ERR_NONE) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
                         "mod_webkdc: webauth_user_config failed: %s",
                         webauth_error_message(rc.ctx, status));
            return DECLINED;
        }
    }

    if (strcmp(r->handler, "webkdc")) {
        return DECLINED;
    }

    req_content_type = apr_table_get(r->headers_in, "content-type");

    if (!req_content_type || strcmp(req_content_type, "text/xml")) {
        return HTTP_BAD_REQUEST;
    }

    if (r->method_number != M_POST) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    ap_set_content_type(r, "text/xml");
    return parse_request(&rc);
}


/*
 * called on restarts
 */
static apr_status_t
mod_webkdc_cleanup(void *data)
{
    server_rec *s = (server_rec*) data;
    server_rec *t;
    struct config *sconf;

    sconf = ap_get_module_config(s->module_config, &webkdc_module);

    if (sconf->debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_webkdc: cleanup");
    }

    /* walk through list of services and clean up */
    for (t=s; t; t=t->next) {
        struct config *tconf;

        tconf = ap_get_module_config(t->module_config, &webkdc_module);
        if (tconf->ring && tconf->free_ring) {
            if (sconf->debug) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                             "mod_webkdc: cleanup ring: %s",
                             tconf->keyring_path);
            }
            webauth_keyring_free(tconf->ring);
            tconf->ring = NULL;
            tconf->free_ring = 0;
        }
    }
    return APR_SUCCESS;
}

/*
 * called after config has been loaded in parent process
 */
static int
mod_webkdc_init(apr_pool_t *pconf, apr_pool_t *plog UNUSED,
                apr_pool_t *ptemp, server_rec *s)
{
    struct config *sconf;
    server_rec *scheck;
    char *version;

    sconf = ap_get_module_config(s->module_config, &webkdc_module);

    if (sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "mod_webkdc: initializing");

    apr_pool_cleanup_register(pconf, s,
                              mod_webkdc_cleanup,
                              apr_pool_cleanup_null);

    for (scheck=s; scheck; scheck=scheck->next) {
        webkdc_config_init(scheck, sconf, ptemp);
    }

    version = apr_pstrcat(ptemp, "WebKDC/", webauth_info_version(), NULL);
    ap_add_version_component(pconf, version);

    if (sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "mod_webkdc: initialized (%s) (%s)",
                     webauth_info_version(),
                     webauth_info_build());

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
