/*
 * mod_webdc
 */ 

#include "mod_webkdc.h"

/* attr list macros to make code easier to read and audit 
 * we don't need to check error codes since we are using
 * WA_F_NONE, which doesn't allocate any memory.
 */

#define ADD_STR(name,value) \
       webauth_attr_list_add_str(alist, name, value, 0, WA_F_NONE)

#define ADD_PTR(name,value, len) \
       webauth_attr_list_add(alist, name, value, len, WA_F_NONE)

#define ADD_TIME(name,value) \
       webauth_attr_list_add_time(alist, name, value, WA_F_NONE)

#define SET_APP_STATE(state,len)     ADD_PTR(WA_TK_APP_STATE, state, len)
#define SET_COMMAND(cmd)             ADD_STR(WA_TK_COMMAND, cmd)
#define SET_CRED_DATA(data, len)     ADD_PTR(WA_TK_CRED_DATA, data, len)
#define SET_CRED_TYPE(type)          ADD_STR(WA_TK_CRED_TYPE, type)
#define SET_CREATION_TIME(time)      ADD_TIME(WA_TK_CREATION_TIME, time)
#define SET_ERROR_CODE(code)         ADD_STR(WA_TK_ERROR_CODE, code)
#define SET_ERROR_MESSAGE(msg)       ADD_STR(WA_TK_ERROR_MESSAGE, msg)
#define SET_EXPIRATION_TIME(time)    ADD_TIME(WA_TK_EXPIRATION_TIME, time)
#define SET_INACTIVITY_TIMEOUT(to)   ADD_STR(WA_TK_INACTIVITY_TIMEOUT, to)
#define SET_SESSION_KEY(key,len)     ADD_PTR(WA_TK_SESSION_KEY, key, len)
#define SET_LASTUSED_TIME(time)      ADD_TIME(WA_TK_LASTUSED_TIME, time)
#define SET_PROXY_TYPE(type)         ADD_STR(WA_TK_PROXY_TYPE, type)
#define SET_PROXY_DATA(data,len)     ADD_PTR(WA_TK_PROXY_DATA, data, len)
#define SET_PROXY_SUBJECT(sub)       ADD_STR(WA_TK_PROXY_SUBJECT, sub)
#define SET_REQUEST_REASON(r)        ADD_STR(WA_TK_REQUEST_REASON, r)
#define SET_REQUESTED_TOKEN_TYPE(t)  ADD_STR(WA_TK_REQUESTED_TOKEN_TYPE, t)
#define SET_RETURN_URL(url)          ADD_STR(WA_TK_RETURN_URL, url)
#define SET_SUBJECT(s)               ADD_STR(WA_TK_SUBJECT, s)
#define SET_SUBJECT_AUTH(sa)         ADD_STR(WA_TK_SUBJECT_AUTH, sa)
#define SET_SUBJECT_AUTH_DATA(d,l)   ADD_PTR(WA_TK_SUBJECT_AUTH_DATA, d, l)
#define SET_TOKEN_TYPE(type)         ADD_STR(WA_TK_TOKEN_TYPE, type)
#define SET_WEBKDC_TOKEN(d,l)        ADD_PTR(WA_TK_WEBKDC_TOKEN, d, l)

/* initiaized in child */
apr_thread_mutex_t *g_keyring_mutex;

/*
 * generate <errorResponse> message
 */
static int
generate_errorResponse(MWK_REQ_CTXT *rc, int ec, const char *message,
                       const char*mwk_func, int log)
{
    char ec_buff[32];
    sprintf(ec_buff,"%d", ec);

    if (message == NULL) {
        message ="";
    }
    ap_rvputs(rc->r, 
              "<errorResponse><errorCode>",
              ec_buff,
              "</errorCode><errorMessage>",
              apr_xml_quote_string(rc->r->pool, message, 0),
              "</errorMessage></errorResponse>",
              NULL);
    ap_rflush(rc->r);

    if (log) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server, 
                     "mod_webkdc: %s: %s", mwk_func, message);
    }
    return OK;
}

static void
keyring_mutex(MWK_REQ_CTXT *rc, int lock)
{
#if APR_HAS_THREADS

    apr_status_t astatus;

    //    ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
    //                 "mod_webkdc: keyring_mutex: (%d) ignored", lock);
    //    return;

    if (g_keyring_mutex != NULL) {
        if (lock)
            astatus = apr_thread_mutex_lock(g_keyring_mutex);
        else 
            astatus = apr_thread_mutex_unlock(g_keyring_mutex);

        if (astatus != APR_SUCCESS) {
            char errbuff[512];
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                         "mod_webkdc: keyring_mutex: %s: %s (%d)",
                         lock ? "lock" : "unlock",
                         apr_strerror(astatus, errbuff, sizeof(errbuff)-1),
                         astatus);
            /* FIXME: now what? */
        }
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webkdc: keyring_mutex: g_keyring_mutex is NULL");
        /* FIXME: now what? */
        }
#endif
}

/* 
 * should only be called (and result used) while you have
 * the keyring_mutex.
 */

static WEBAUTH_KEYRING *
get_keyring(MWK_REQ_CTXT *rc) {
    int status;
    static WEBAUTH_KEYRING *ring = NULL;

    if (ring != NULL) {
        return ring;
    }

    /* attempt to open up keyring */
    status = webauth_keyring_read_file(rc->sconf->keyring_path, &ring);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r, status, NULL,
                              "get_keyring", "webauth_keyring_read_file");
    } else {
        /* FIXME: should probably make sure we have at least one
           valid (not expired/postdated) key in the ring */
    }
    return ring;
}

/*
 * returns new attr list, or NULL if there was an error
 */

static WEBAUTH_ATTR_LIST *
new_attr_list_er(MWK_REQ_CTXT *rc, const char *mwk_func) 
{
    WEBAUTH_ATTR_LIST *alist = webauth_attr_list_new(32);
    if (alist == NULL) {
        generate_errorResponse(rc, WA_PEC_SERVER_FAILURE, 
                               "no memory for attr list", mwk_func, 0);
    }
    return alist;
}

static int
make_token_er(MWK_REQ_CTXT *rc, WEBAUTH_ATTR_LIST *alist, time_t hint,
              char **out_token, int *out_len, 
              int base64_encode,
              const char *mwk_func)
{
    WEBAUTH_KEYRING *ring;
    char *buffer;
    int status, elen, olen;

    elen = webauth_token_encoded_length(alist);
    buffer = (char*)apr_palloc(rc->r->pool, elen);
    status = WA_ERR_NONE;

    keyring_mutex(rc, 1); /********************* LOCKING! ************/

    ring = get_keyring(rc);
    if (ring != NULL) {
        status = webauth_token_create(alist, hint, buffer, &olen, elen, ring);
    }

    keyring_mutex(rc, 0); /********************* UNLOCKING! ************/

    if (ring == NULL) {
        generate_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                               "no keyring", mwk_func, 1);
        return 0;
    }

    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r, status, NULL, mwk_func,
                              "webauth_token_create");
        generate_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                               "token create failed", mwk_func, 0);
        return 0;
    }

    if (base64_encode) {
        *out_token = (char*) 
            apr_palloc(rc->r->pool, apr_base64_encode_len(olen));
        *out_len = apr_base64_encode(*out_token, buffer, olen);
    } else {
        *out_token = buffer;
        *out_len = olen;
    }
    return 1;
}


static int
make_token_with_key_er(MWK_REQ_CTXT *rc, 
                       WEBAUTH_KEY *key,
                       WEBAUTH_ATTR_LIST *alist, time_t hint,
                       char **out_token, int *out_len, 
                       int base64_encode,
                       const char *mwk_func)
{
    char *buffer;
    int status, elen, olen;

    elen = webauth_token_encoded_length(alist);
    buffer = (char*)apr_palloc(rc->r->pool, elen);

    status = webauth_token_create_with_key(alist, hint, buffer, 
                                           &olen, elen, key);

    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r, status, NULL, mwk_func,
                              "webauth_token_create_with_key");
        generate_errorResponse(rc, WA_PEC_SERVER_FAILURE,
                               "token create failed", mwk_func, 0);
        return 0;
    }

    if (base64_encode) {
        *out_token = (char*) 
            apr_palloc(rc->r->pool, apr_base64_encode_len(olen));
        *out_len = apr_base64_encode(*out_token, buffer, olen);
    } else {
        *out_token = buffer;
        *out_len = olen;
    }
    return 1;
}


/*
 * log information about a bad element in XML and generate errorResponse
 */

static void
unknown_element_er(MWK_REQ_CTXT *rc, 
                const char *mwk_func, const char *parent, const char *u)
{
    char *msg = apr_psprintf(rc->r->pool, "unknown element in <%s>: <%s>",
                             parent, u);
    generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg, mwk_func, 1);
}

/*
 * get an attr from an element. if required and not found, we
 * log an error and generate an errorResponse.
 */
static const char*
get_attr_value_er(MWK_REQ_CTXT *rc,apr_xml_elem *e, 
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
            generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                                   msg, mwk_func, 1);
    }
    return NULL;
}


/*
 * find an element in the specified element. if required and not found, we
 * log an error and generate an errorResponse.
 */
apr_xml_elem *
get_element_er(MWK_REQ_CTXT *rc,apr_xml_elem *e, 
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
            generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg,
                                   mwk_func, 1);
    }
    return NULL;
}

/*
 * search through subject credentials for a proxy-token of the requested
 * type.
 */
static MWK_PROXY_TOKEN *
find_proxy_token_er(MWK_REQ_CTXT *rc,
                    MWK_SUBJECT_CREDENTIAL *sub_cred, 
                    const char *type,
                    const char *mwk_func) 
{
    int i;
    char *msg;
    if (strcmp(sub_cred->type, "proxy") == 0) {
        for (i=0; i < sub_cred->u.proxy.num_proxy_tokens; i++) {
            if (strcmp(sub_cred->u.proxy.pt[i].proxy_type, type) == 0) {
                return  &sub_cred->u.proxy.pt[i];
            }
        }
    }
    msg = apr_psprintf(rc->r->pool, "need a proxy-token of type: %s", type);
    generate_errorResponse(rc, WA_PEC_PROXY_TOKEN_REQUIRED, msg, mwk_func, 1);
    return NULL;
}

/*
 * parse a <serviceToken>, which should be base64-encoded.
 * return 1 on success, 0 on error.
 * logs all errors and generates errorResponse if need be.
 */
static int
parse_service_token_er(MWK_REQ_CTXT *rc, char *token,
                       MWK_SERVICE_TOKEN *st)
{
    WEBAUTH_ATTR_LIST *alist;
    WEBAUTH_KEYRING *ring;
    int blen, status, i, ok;
    const char *tt;
    static const char *mwk_func = "parse_service_token";

    ok = 0;

    blen = apr_base64_decode(token, token);
    status = WA_ERR_NONE;

    /* parse the token, TTL is zero because service-tokens don't have ttl,
     * just expiration
     */

    keyring_mutex(rc, 1); /********************* LOCKING! ************/

    ring = get_keyring(rc);
    if (ring != NULL) {
        status = webauth_token_parse(token, blen, 0, ring, &alist);
    }
    keyring_mutex(rc, 0); /********************* UNLOCKING! ************/

    if (ring == NULL) {
        generate_errorResponse(rc, WA_PEC_SERVER_FAILURE, "no keyring",
                               mwk_func, 1);
        return 0;
    }

    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r, status, NULL, mwk_func,
                              "webauth_token_parse");
        if (status == WA_ERR_TOKEN_EXPIRED) {
            generate_errorResponse(rc, WA_PEC_SERVICE_TOKEN_EXPIRED,
                                   "service token was expired", mwk_func, 0);
        } else if (status == WA_ERR_BAD_HMAC) {
            generate_errorResponse(rc, WA_PEC_SERVICE_TOKEN_INVALID,
                                   "can't decrypt service token", mwk_func, 0);
        } else {
            generate_errorResponse(rc, WA_PEC_SERVICE_TOKEN_INVALID,
                                   "error parsing token", mwk_func, 0);
        }
        return 0;
    }

    /* make sure its a service-token */
    tt = mwk_get_str_attr(alist, WA_TK_TOKEN_TYPE, rc->r, mwk_func, NULL);
    if ((tt == NULL) || (strcmp(tt, WA_TT_WEBKDC_SERVICE) != 0)) {
        generate_errorResponse(rc, WA_PEC_SERVICE_TOKEN_INVALID, 
                               "not a service token", mwk_func, 1);
        goto cleanup;
    }

    /* pull out session key */
    status = webauth_attr_list_find(alist, WA_TK_SESSION_KEY, &i);
    if (i == -1) {
        generate_errorResponse(rc, WA_PEC_SERVICE_TOKEN_INVALID, 
                               "missing session key", mwk_func, 1);
        goto cleanup;
    }
    st->key.length = alist->attrs[i].length;
    st->key.data = apr_palloc(rc->r->pool, st->key.length);
    memcpy(st->key.data, alist->attrs[i].value, st->key.length);
    st->key.type = WA_AES_KEY; /* HARCODED */

    /* pull out subject */
    status = webauth_attr_list_find(alist, WA_TK_SUBJECT, &i);
    if (i == -1) {
        generate_errorResponse(rc, WA_PEC_SERVICE_TOKEN_INVALID, 
                               "missing subject", mwk_func, 1);
        goto cleanup;
    }
    st->subject = apr_pstrdup(rc->r->pool, (char*)alist->attrs[i].value);
    ok = 1;

 cleanup:
    webauth_attr_list_free(alist);
    return ok;
}

/*
 * parse a proxy-token, which should be base64-encoded.
 * return 1 on success, 0 on error.
 * logs all errors and generates errorResponse if need be.
 */
static int
parse_webkdc_proxy_token_er(MWK_REQ_CTXT *rc, char *token,
                  MWK_PROXY_TOKEN *pt)
{
    WEBAUTH_ATTR_LIST *alist;
    WEBAUTH_KEYRING *ring;
    int blen, status, i, ok;
    const char *tt;
    static const char *mwk_func = "parse_webkdc_proxy_token";

    if (token == NULL) {
            generate_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID,
                                   "no proxy token present", mwk_func, 1);
            return 0;
    }

    blen = apr_base64_decode(token, token);
    status = WA_ERR_NONE;
    ok = 0;

    /* parse the token, TTL is zero because proxy-tokens don't have ttl,
     * just expiration
     */

    keyring_mutex(rc, 1); /********************* LOCKING! ************/

    ring = get_keyring(rc);
    if (ring != NULL) {
        status = webauth_token_parse(token, blen, 0, ring, &alist);
    }
    keyring_mutex(rc, 0); /********************* UNLOCKING! ************/

    if (ring == NULL) {
        generate_errorResponse(rc, WA_PEC_SERVER_FAILURE, "no keyring",
                               mwk_func, 1);
        return 0;
    }

    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r, status, NULL, mwk_func,
                              "webauth_token_parse");
        if (status == WA_ERR_TOKEN_EXPIRED) {
            generate_errorResponse(rc, WA_PEC_PROXY_TOKEN_EXPIRED,
                                   "proxy token was expired", mwk_func, 0);
        } else if (status == WA_ERR_BAD_HMAC) {
            generate_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID,
                                   "can't decrypt proxy token", mwk_func, 0);
        } else {
            generate_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID,
                                   "error parsing token", mwk_func, 0);
        }
        return 0;
    }

    /* make sure its a proxy-token */
    tt = mwk_get_str_attr(alist, WA_TK_TOKEN_TYPE, rc->r, mwk_func, NULL);
    if ((tt == NULL) || (strcmp(tt, WA_TT_WEBKDC_PROXY) != 0)) {
        generate_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID, 
                               "not a webkdc-proxy token", mwk_func, 1);
        goto cleanup;
    }

    /* pull out proxy-data key */
    status = webauth_attr_list_find(alist, WA_TK_PROXY_DATA, &i);
    if (i == -1) {
        generate_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID, 
                               "missing proxy data", mwk_func, 1);
        goto cleanup;
    }
    pt->proxy_data_len = alist->attrs[i].length;
    pt->proxy_data = apr_palloc(rc->r->pool, pt->proxy_data_len);
    memcpy(pt->proxy_data, alist->attrs[i].value, pt->proxy_data_len);

    /* pull out subject */
    status = webauth_attr_list_find(alist, WA_TK_SUBJECT, &i);
    if (i == -1) {
        generate_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID, 
                               "missing subject", mwk_func, 1);
        goto cleanup;
    }
    pt->subject = apr_pstrdup(rc->r->pool, (char*)alist->attrs[i].value);

    /* pull out proxy type */
    status = webauth_attr_list_find(alist, WA_TK_PROXY_TYPE, &i);
    if (i == -1) {
        generate_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID, 
                               "missing proxy type", mwk_func, 1);
        goto cleanup;
    }
    pt->proxy_type = apr_pstrdup(rc->r->pool, (char*)alist->attrs[i].value);

    /* pull out proxy subject */
    status = webauth_attr_list_find(alist, WA_TK_PROXY_SUBJECT, &i);
    if (i == -1) {
        generate_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID, 
                               "missing proxy subject type", mwk_func, 1);
        goto cleanup;
    }
    pt->proxy_subject = apr_pstrdup(rc->r->pool, (char*)alist->attrs[i].value);

    /* pull out expiration */
    status = webauth_attr_list_get_time(alist, WA_TK_EXPIRATION_TIME,
                                        &pt->expiration, WA_F_NONE);
    if (status != WA_ERR_NONE) {
        generate_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID, 
                               "missing expiration", mwk_func, 1);
        goto cleanup;
    }

    ok = 1;

 cleanup:
    webauth_attr_list_free(alist);
    return ok;
}


/*
 * parse a login-token, which should be base64-encoded.
 * return 1 on success, 0 on error.
 * logs all errors and generates errorResponse if need be.
 */
static int
parse_login_token_er(MWK_REQ_CTXT *rc, char *token,
                     MWK_LOGIN_TOKEN *lt)
{
    WEBAUTH_ATTR_LIST *alist;
    WEBAUTH_KEYRING *ring;
    int blen, status, i, ok;
    const char *tt;
    static const char *mwk_func = "parse_login_token_er";

    if (token == NULL) {
            generate_errorResponse(rc, WA_PEC_LOGIN_TOKEN_INVALID,
                                   "no login token present", mwk_func, 1);
            return 0;
    }
    
    blen = apr_base64_decode(token, token);
    status = WA_ERR_NONE;
    ok = 0;

    /* parse the token, with a TTL */

    keyring_mutex(rc, 1); /********************* LOCKING! ************/

    ring = get_keyring(rc);
    if (ring != NULL) {
        status = webauth_token_parse(token, blen,
                                     rc->sconf->token_max_ttl,
                                     ring, &alist);
    }
    keyring_mutex(rc, 0); /********************* UNLOCKING! ************/

    if (ring == NULL) {
        generate_errorResponse(rc, WA_PEC_SERVER_FAILURE, "no keyring",
                               mwk_func, 1);
        return 0;
    }

    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r, status, NULL, mwk_func,
                              "webauth_token_parse");
        if (status == WA_ERR_TOKEN_STALE) {
            generate_errorResponse(rc, WA_PEC_LOGIN_TOKEN_STALE,
                                   "login token was stale", mwk_func, 0);
        } else if (status == WA_ERR_BAD_HMAC) {
            generate_errorResponse(rc, WA_PEC_LOGIN_TOKEN_INVALID,
                                   "can't decrypt login token", mwk_func, 0);
        } else {
            generate_errorResponse(rc, WA_PEC_LOGIN_TOKEN_INVALID,
                                   "error parsing token", mwk_func, 0);
        }
        return 0;
    }

    /* make sure its a login-token */
    tt = mwk_get_str_attr(alist, WA_TK_TOKEN_TYPE, rc->r, mwk_func, NULL);
    if ((tt == NULL) || (strcmp(tt, WA_TT_LOGIN) != 0)) {
        generate_errorResponse(rc, WA_PEC_LOGIN_TOKEN_INVALID, 
                               "not a login token", mwk_func, 1);
        goto cleanup;
    }

    /* pull out username */
    status = webauth_attr_list_find(alist, WA_TK_USERNAME, &i);
    if (i == -1) {
        generate_errorResponse(rc, WA_PEC_LOGIN_TOKEN_INVALID, 
                               "missing username", mwk_func, 1);
        goto cleanup;
    }
    lt->username = apr_pstrdup(rc->r->pool, (char*)alist->attrs[i].value);

    /* pull out password */
    status = webauth_attr_list_find(alist, WA_TK_PASSWORD, &i);
    if (i == -1) {
        generate_errorResponse(rc, WA_PEC_LOGIN_TOKEN_INVALID, 
                               "missing password", mwk_func, 1);
        goto cleanup;
    }
    lt->password = apr_pstrdup(rc->r->pool, (char*)alist->attrs[i].value);
    ok = 1;

 cleanup:
    webauth_attr_list_free(alist);
    return ok;
}

/*
 * parse a <requestToken> from a POST, which should be base64-encoded.
 * return 1 on success, 0 on error.
 * logs all errors and generates errorResponse if need be.
 */
static int
parse_request_token_er(MWK_REQ_CTXT *rc, 
                       char *token,
                       MWK_SERVICE_TOKEN *st,
                       MWK_REQUEST_TOKEN *rt,
                       int cmd_only)
{
    WEBAUTH_ATTR_LIST *alist;
    int blen, status, i, ok;
    const char *tt;
    static const char *mwk_func = "parse_xml_request_token";

    blen = apr_base64_decode(token, token);

    ok = 0;

    /* parse the token, use TTL  */
    status = webauth_token_parse_with_key(token, blen, 
                                          rc->sconf->token_max_ttl,
                                          &st->key, &alist);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r, status, NULL, "parse_xml_request_token", 
                              "webauth_token_parse");
        if (status == WA_ERR_TOKEN_STALE) {
            generate_errorResponse(rc, WA_PEC_REQUEST_TOKEN_STALE,
                                   "request token was stale", mwk_func, 0);
        } else if (status == WA_ERR_BAD_HMAC) {
            generate_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID,
                                   "can't decrypt request token", mwk_func, 0);
        } else {
            generate_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID,
                                   "error parsing token", mwk_func, 0);
        }
        return 0;
    }

    /* make sure its a request-token */
    tt = mwk_get_str_attr(alist, WA_TK_TOKEN_TYPE, rc->r, mwk_func, NULL);
    if ((tt == NULL) || (strcmp(tt, WA_TT_REQUEST) != 0)) {
        generate_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID, 
                               "not a request token", mwk_func, 1);
        goto cleanup;
    }

    if (cmd_only) {
        /* pull out command */
        status = webauth_attr_list_find(alist, WA_TK_COMMAND, &i);
        if (i == -1) {
            generate_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID, 
                                   "missing command", mwk_func, 1);
            goto cleanup;
        }
        rt->cmd = apr_pstrdup(rc->r->pool, 
                              (char*)alist->attrs[i].value);
        ok = 1;
        goto cleanup;
    }

    /* else expecting full request-token */

    /* pull out optional WA_TK_APP_STATE */
    status = webauth_attr_list_find(alist, WA_TK_APP_STATE, &i);
    if (i != -1) {
        rt->app_state_len = alist->attrs[i].length;
        rt->app_state = apr_palloc(rc->r->pool, rt->app_state_len);
        memcpy(rt->app_state, alist->attrs[i].value, rt->app_state_len);
    } else {
        rt->app_state_len = 0;
        rt->app_state = NULL;
    }

    /* pull out return-url */
    status = webauth_attr_list_find(alist, WA_TK_RETURN_URL, &i);
    if (i == -1) {
        generate_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID, 
                               "missing return url", mwk_func, 1);
        goto cleanup;
    }
    rt->return_url = apr_pstrdup(rc->r->pool, (char*)alist->attrs[i].value);

    /* pull out request-reason */
    status = webauth_attr_list_find(alist, WA_TK_REQUEST_REASON, &i);
    if (i == -1) {
        generate_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID, 
                               "missing request-reason", mwk_func, 1);
        goto cleanup;
    }
    rt->request_reason = 
        apr_pstrdup(rc->r->pool, (char*)alist->attrs[i].value);

    /* pull out requested-token-type */
    status = webauth_attr_list_find(alist, WA_TK_REQUESTED_TOKEN_TYPE, &i);
    if (i == -1) {
        generate_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID, 
                               "missing requested token type", mwk_func, 1);
        goto cleanup;
    }

    rt->requested_token_type = 
        apr_pstrdup(rc->r->pool, (char*)alist->attrs[i].value);

    if (strcmp(rt->requested_token_type, "id") == 0) {
        /* pull out subject-auth-type */
        status = webauth_attr_list_find(alist, WA_TK_SUBJECT_AUTH, &i);
        if (i == -1) {
            generate_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID, 
                                   "missing subject auth type", mwk_func, 1);
            goto cleanup;
        }

        rt->u.subject_auth_type = 
            apr_pstrdup(rc->r->pool, (char*)alist->attrs[i].value);
    } else if (strcmp(rt->requested_token_type, "proxy") == 0) {
        /* pull out proxy-type */
        status = webauth_attr_list_find(alist, WA_TK_PROXY_TYPE, &i);
        if (i == -1) {
            generate_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID, 
                                   "missing proxy type", mwk_func, 1);
            goto cleanup;
        }

        rt->u.proxy_type = 
            apr_pstrdup(rc->r->pool, (char*)alist->attrs[i].value);
    } else {
        char *msg = apr_psprintf(rc->r->pool, 
                                 "unknown requested-token-typee: %s",
                                 rt->requested_token_type);
        generate_errorResponse(rc, WA_PEC_REQUEST_TOKEN_INVALID, msg, 
                               mwk_func, 1);
        goto cleanup;
    }

    ok = 1;

 cleanup:
    webauth_attr_list_free(alist);
    return ok;
}

/*
 * returns 1 on success, 0 on failure
 */
static int
parse_requesterCredential_er(MWK_REQ_CTXT *rc, apr_xml_elem *e, 
                             MWK_REQUESTER_CREDENTIAL *req_cred)
{
    int status;
    apr_xml_elem *child;
    static const char*mwk_func = "parse_requesterCredential";
    const char *at = get_attr_value_er(rc, e, "type",  1, mwk_func);

    if (at == NULL)
        return 0;

    req_cred->type = apr_pstrdup(rc->r->pool, at);

    if (strcmp(at, "service") == 0) {
        int st_p = 0, rt_p = 0;

        for (child = e->first_child; child; child = child->next) {
	    if (strcmp(child->name, "serviceToken") == 0) {
                const char *token = mwk_get_elem_text(rc, e, "");
                st_p = 1;
                if (!parse_service_token_er(rc, (char*)token, 
                                            &req_cred->u.service.st)) {
                    return 0;
                }
                /* pull out subject from service token */
                req_cred->subject = req_cred->u.service.st.subject;
	    } else if (strcmp(child->name, "requestToken") == 0) {
                const char *token = mwk_get_elem_text(rc, e, "");
                rt_p = 1;
                if (!parse_request_token_er(rc, (char*)token, 
                                            &req_cred->u.service.st,
                                            &req_cred->u.service.rt, 1)) {
                    return 0;
                }
	    } else {
                unknown_element_er(rc, mwk_func, e->name, child->name);
                return 0;
	    }
	}

	if (!(rt_p && st_p)) {
            generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                                   "<requestCredential> must have "
                                   "<serviceToken> and <requestToken>",
                                   mwk_func, 1);
            return 0;
	}
        return 1;
    } else if (strcmp(at, "krb5") == 0) {
        const char *req;
        int blen;
        char *bin_req, *client_principal;
        WEBAUTH_KRB5_CTXT *ctxt = mwk_get_webauth_krb5_ctxt(rc->r, mwk_func);
        if (ctxt == NULL) {
            /* mwk_get_webauth_krb5_ctxt already logged error */
            return generate_errorResponse(rc, WA_PEC_SERVER_FAILURE, 
                                          "server failure", mwk_func, 0);
            return 0;
        }

        req = mwk_get_elem_text(rc, e, "");
        bin_req = (char*)apr_palloc(rc->r->pool, 
                                    apr_base64_decode_len(req));
        blen = apr_base64_decode(bin_req, req);

        status = webauth_krb5_rd_req(ctxt, bin_req, blen,
                                     rc->sconf->keytab_path,
                                     &client_principal);

        if (status != WA_ERR_NONE) {
            char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                                  "webauth_krb5_rd_req");
            generate_errorResponse(rc, WA_PEC_REQUESTER_KRB5_CRED_INVALID, msg,
                                   mwk_func, 1);
            webauth_krb5_free(ctxt);
            return 0;
        }
        webauth_krb5_free(ctxt);
        req_cred->subject = apr_pstrcat(rc->r->pool, "krb5:", client_principal,
                                        NULL);
        free(client_principal);
        return 1;
    } else {
        char *msg = apr_psprintf(rc->r->pool, 
                                 "unknown <requesterCredential> type: %s",
                                 at);
            generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                                   msg, mwk_func, 1);
            return 0;
    }
    return 0;
}


/*
 * returns 1 on success, 0 on failure
 */
static int
parse_subjectCredential_er(MWK_REQ_CTXT *rc, apr_xml_elem *e, 
                           MWK_SUBJECT_CREDENTIAL *sub_cred)
{
    static const char*mwk_func = "parse_subjectCredential";

    const char *at = get_attr_value_er(rc, e, "type",  1, mwk_func);

    if (at == NULL)
        return 0;

    sub_cred->type = apr_pstrdup(rc->r->pool, at);

    if (strcmp(at, "proxy") == 0) {
        int n  = 0;
        apr_xml_elem *child;
        /* attempt to parse each proxy token */
        for (child = e->first_child; child; child = child->next) {
            if (strcmp(child->name, "proxyToken") == 0) {
                char *token = mwk_get_elem_text(rc, child, NULL);
                if (!parse_webkdc_proxy_token_er(rc, token, 
                                                 &sub_cred->u.proxy.pt[n]))
                    return 0;
                n++;
            } else {
                unknown_element_er(rc, mwk_func, e->name, child->name);
                return 0;
            }
        }
        sub_cred->u.proxy.num_proxy_tokens = n;
    } else if (strcmp(at, "login") == 0) {
        char *token;
        apr_xml_elem *login_token = get_element_er(rc, e,
                                                   "loginToken", 1, mwk_func);
        if (login_token == NULL)
            return 0;

        token = mwk_get_elem_text(rc, login_token, "");

        if (!parse_login_token_er(rc, token, &sub_cred->u.lt))
            return 0;
    } else {
        char *msg = apr_psprintf(rc->r->pool, 
                                 "unknown <subjectCredential> type: %s",
                                 at);
            generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg,
                                   mwk_func, 1);
            return 0;
    }
    return 1;
}

/*
 * returns 1 on success, 0 on failure
 */
static int
create_service_token_from_req_er(MWK_REQ_CTXT *rc, 
                                 MWK_REQUESTER_CREDENTIAL *req_cred,
                                 MWK_RETURNED_TOKEN *rtoken)
{
    static const char *mwk_func="create_service_token_from_req_er";
    unsigned char session_key[WA_AES_128];
    int status, len, ok;
    time_t creation, expiration;
    WEBAUTH_ATTR_LIST *alist;
    /* only create service tokens from krb5 creds */
    if (strcmp(req_cred->type, "krb5") != 0) {
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                               "can only create service-tokens with "
                               "<requesterCredential> of type krb",
                               mwk_func, 1);
        return 0;
    }

    /*FIXME: ACL CHECK: subject allowed to get a service token? */

    status = webauth_random_key(session_key, sizeof(session_key));

    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(rc->r, status, NULL, mwk_func,
                              "webauth_random_key");
        generate_errorResponse(rc, WA_PEC_SERVER_FAILURE, 
                               "can't generate session key", mwk_func, 0);
        return 0;
    }

    time(&creation);
    expiration = creation + rc->sconf->service_token_lifetime;

    alist = new_attr_list_er(rc, mwk_func);
    if (alist == NULL)
        return 0;

    SET_TOKEN_TYPE(WA_TT_WEBKDC_SERVICE);
    SET_SESSION_KEY(session_key, sizeof(session_key));
    SET_SUBJECT(req_cred->subject);
    SET_CREATION_TIME(creation);
    SET_EXPIRATION_TIME(expiration);

    ok = make_token_er(rc, alist, creation,
                       (char**)&rtoken->token_data, &len, 1, mwk_func);

    webauth_attr_list_free(alist);

    if (!ok)
        return 0;

    rtoken->expires = apr_psprintf(rc->r->pool, "%d", (int)expiration);

    len = sizeof(session_key);
    rtoken->session_key = (char*) 
        apr_palloc(rc->r->pool, apr_base64_encode_len(len));
    apr_base64_encode((char*)rtoken->session_key, session_key, len);

    return 1;
}


/*
 * returns 1 on success, 0 on failure.
 * sad is allocated from request pool
 */
static int 
get_krb5_sad(MWK_REQ_CTXT *rc, 
             MWK_REQUESTER_CREDENTIAL *req_cred,
             MWK_PROXY_TOKEN *sub_pt,
             unsigned char **sad,
             int *sad_len,
             const char *mwk_func)
{
    WEBAUTH_KRB5_CTXT *ctxt;
    int status;
    char *server_principal;
    unsigned char *temp_sad;

    ctxt = mwk_get_webauth_krb5_ctxt(rc->r, mwk_func);
    if (ctxt == NULL) {
        /* mwk_get_webauth_krb5_ctxt already logged error */
        return generate_errorResponse(rc, WA_PEC_SERVER_FAILURE, 
                                      "server failure (webauth_krb5_new)", 
                                      mwk_func, 0);
        return 0;
    }

    status = webauth_krb5_init_via_tgt(ctxt, sub_pt->proxy_data, 
                                       sub_pt->proxy_data_len, NULL);

    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r,
                                              status, ctxt,
                                              "webauth_krb5_export_ticket");
        webauth_krb5_free(ctxt);
        /* FIXME: probably need to examine errors a little more closely
         *        to determine if we should return a proxy-token error
         *        or a server-failure.
         */
        generate_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID, msg, 
                               mwk_func, 1);
        return 0;
    }

    server_principal = req_cred->u.service.st.subject;
    if (strncmp(server_principal, "krb5:", 5) == 0) {
        server_principal += 5;
    }

    status = webauth_krb5_mk_req(ctxt, server_principal, &temp_sad, sad_len);

    /* we can't free the krb5 ctxt yet as we might need it for logging */

    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                              "webauth_krb5_mk_req");
        webauth_krb5_free(ctxt);
        /* FIXME: probably need to examine errors a little more closely
         *        to determine if we should return a proxy-token error
         *        or a server-failure.
         */
        generate_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID, msg,
                               mwk_func, 1);
        return 0;
    } else {
        webauth_krb5_free(ctxt);
        *sad = apr_palloc(rc->r->pool, *sad_len);
        memcpy(*sad,  temp_sad, *sad_len);
        free(temp_sad);
        return 1;
    }
}

/*
 * returns 1 on success, 0 on failure
 */
static int
create_id_token_from_req_er(MWK_REQ_CTXT *rc, 
                            const char *auth_type,
                            MWK_REQUESTER_CREDENTIAL *req_cred,
                            MWK_SUBJECT_CREDENTIAL *sub_cred,
                            MWK_RETURNED_TOKEN *rtoken)
{
    static const char *mwk_func="create_id_token_from_req_er";
    int tlen, sad_len, ok;
    time_t creation, expiration;
    WEBAUTH_ATTR_LIST *alist;
    MWK_PROXY_TOKEN *sub_pt;
    const char *subject;
    unsigned char *sad;
    
    /* only create id tokens from service creds */
    if (strcmp(req_cred->type, "service") != 0) {

        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                               "can only create id-tokens with "
                               "<requesterCredential> of type service",
                               mwk_func, 1);
        return 0;
    }

    /* make sure we have a subject cred with a type='proxy' */
    if (strcmp(sub_cred->type, "proxy") != 0) {
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                               "can only create id-tokens with "
                               "<subjectCredential> of type proxy",
                               mwk_func, 1);
        return 0;
    }

    /* FIXME: ACL CHECK: requester allowed to get an id token
     *        using subject cred?
     */

    sad = NULL;
    subject = NULL;

    if (strcmp(auth_type, "webkdc") == 0) {
        /* FIXME: are we going to have a webkc proxy type? */
        sub_pt = find_proxy_token_er(rc, sub_cred, "krb5", mwk_func);
        if (sub_pt == NULL)
            return 0;
    } else if (strcmp(auth_type, "krb5") == 0) {
        /* find a proxy-token of the right type */
        sub_pt = find_proxy_token_er(rc, sub_cred, "krb5", mwk_func);
        if (sub_pt == NULL)
            return 0;
        if (!get_krb5_sad(rc, req_cred, sub_pt, &sad, &sad_len, mwk_func)) {
            return 0;
        }

    } else {
        char *msg = apr_psprintf(rc->r->pool, "invalid authenticator type %s",
                                 auth_type);
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg, mwk_func, 1);
        return 0;
    }

    alist = new_attr_list_er(rc, mwk_func);
    if (alist == NULL)
        return 0;

    time(&creation);
    /* expiration comes from expiration of proxy-token */
    expiration = sub_pt->expiration;

    SET_TOKEN_TYPE(WA_TT_ID);
    SET_SUBJECT_AUTH(auth_type);
    if (subject != NULL) {
        SET_SUBJECT(subject);
    }
    if (sad != NULL) {
        SET_SUBJECT_AUTH_DATA(sad, sad_len);
    }
    SET_CREATION_TIME(creation);
    SET_EXPIRATION_TIME(expiration);

    ok = make_token_with_key_er(rc, &req_cred->u.service.st.key,
                                alist, creation,
                                (char**)&rtoken->token_data, 
                                &tlen, 1, mwk_func);
    webauth_attr_list_free(alist);

    return ok;
}

/*
 * returns 1 on success, 0 on failure
 */
static int
create_proxy_token_from_req_er(MWK_REQ_CTXT *rc, 
                               const char *proxy_type,
                               MWK_REQUESTER_CREDENTIAL *req_cred,
                               MWK_SUBJECT_CREDENTIAL *sub_cred,
                               MWK_RETURNED_TOKEN *rtoken)
{
    static const char *mwk_func="create_proxy_token_from_req_er";
    int tlen, wkdc_len, ok;
    time_t creation, expiration;
    WEBAUTH_ATTR_LIST *alist;
    MWK_PROXY_TOKEN *sub_pt;
    unsigned char *wkdc_token;
    
    /* only create proxy tokens from service creds */
    if (strcmp(req_cred->type, "service") != 0) {
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                               "can only create proxy-tokens with "
                               "<requesterCredential> of type service",
                               mwk_func, 1);
        return 0;
    }

    /* make sure we have a subject cred with a type='proxy' */
    if (strcmp(sub_cred->type, "proxy") != 0) {
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                               "can only create proxy-tokens with "
                               "<subjectCredential> of type proxy",
                               mwk_func, 1);
        return 0;
    }

    /* FIXME: ACL CHECK: requester allowed to get a proxy token
     *        using subject cred?
     */


    /* make sure we are creating a proxy-tyoken that has
       the same type as the proxy-token we using to create it */
    sub_pt = find_proxy_token_er(rc, sub_cred, proxy_type, mwk_func);
    if (sub_pt == NULL) 
        return 0;

    /* create the webkdc-proxy-token first, using existing proxy-token */
    alist = new_attr_list_er(rc, mwk_func);
    if (alist == NULL)
        return 0;

    time(&creation);

    /* expiration comes from expiration of proxy-token */
    expiration =  sub_pt->expiration;

    /* make sure to use subject from service-token for new proxy-subject */
    SET_TOKEN_TYPE(WA_TT_WEBKDC_PROXY);
    SET_CREATION_TIME(creation);
    SET_EXPIRATION_TIME(expiration);
    SET_PROXY_TYPE(sub_pt->proxy_type);
    SET_PROXY_SUBJECT(req_cred->u.service.st.subject);
    SET_SUBJECT(sub_pt->subject);
    SET_PROXY_DATA(sub_pt->proxy_data, sub_pt->proxy_data_len);

    ok = make_token_er(rc, alist, creation,
                       (char**)&wkdc_token, &wkdc_len, 0, mwk_func);
    webauth_attr_list_free(alist);

    if (!ok)
        return 0;

    /* now create the proxy-token */
    alist = new_attr_list_er(rc, mwk_func);
    if (alist == NULL)
        return 0;

    SET_TOKEN_TYPE(WA_TT_PROXY);
    SET_PROXY_TYPE(sub_pt->proxy_type);
    SET_SUBJECT(sub_pt->subject);
    SET_WEBKDC_TOKEN(wkdc_token, wkdc_len);
    SET_CREATION_TIME(creation);
    SET_EXPIRATION_TIME(expiration);

    ok = make_token_with_key_er(rc, &req_cred->u.service.st.key,
                                alist, creation,
                                (char**)&rtoken->token_data, 
                                &tlen, 1, mwk_func);
    webauth_attr_list_free(alist);
    return ok;
}

/*
 * returns 1 on success, 0 on failure
 */
static int
create_cred_token_from_req_er(MWK_REQ_CTXT *rc, 
                              apr_xml_elem *e,
                              MWK_REQUESTER_CREDENTIAL *req_cred,
                              MWK_SUBJECT_CREDENTIAL *sub_cred,
                              MWK_RETURNED_TOKEN *rtoken)
{
    static const char *mwk_func="create_cred_token_from_req_er";
    int tlen, ok, status, ticket_len;
    time_t creation, expiration, ticket_expiration;
    WEBAUTH_ATTR_LIST *alist;
    apr_xml_elem *credential_type, *server_principal;
    const char *ct, *sp;
    WEBAUTH_KRB5_CTXT *ctxt;
    MWK_PROXY_TOKEN *sub_pt;
    unsigned char *ticket;
    
    /* only create cred tokens from service creds */
    if (strcmp(req_cred->type, "service") != 0 ) {
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                               "can only create cred-tokens with "
                               "<requesterCredential> of type service",
                               mwk_func, 1);
        return 0;
    }

    /* make sure we have a subject cred with a type='proxy' */
    if (strcmp(sub_cred->type, "proxy") != 0) {
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                               "can only create cred-tokens with "
                               "<subjectCredential> of type proxy",
                               mwk_func, 1);
        return 0;
    }

    /* FIXME: ACL CHECK: requester allowed to get a cred token
     *        using subject cred?
     */

    credential_type = get_element_er(rc, e, "credentialType", 1, mwk_func);

    if (credential_type == NULL)
        return 0;

    ct = mwk_get_elem_text(rc, credential_type, NULL);

    if (ct == NULL) 
        return 0;

    server_principal = get_element_er(rc, e, "serverPrincipal", 1, mwk_func);

    if (server_principal == NULL)
        return 0;

    sp = mwk_get_elem_text(rc, server_principal, NULL);

    if (sp == NULL) 
        return 0;

    /* make sure we are creating a cred-token that has
       the same type as the proxy-token we are using to create it */
    sub_pt = find_proxy_token_er(rc, sub_cred, ct, mwk_func);
    if (sub_pt == NULL)
        return 0;

    /* try to get the credentials  */
    ctxt = mwk_get_webauth_krb5_ctxt(rc->r, mwk_func);
    if (ctxt == NULL) {
        /* mwk_get_webauth_krb5_ctxt already logged error */
        return generate_errorResponse(rc, WA_PEC_SERVER_FAILURE, 
                                      "server failure", mwk_func, 0);
        return 0;
    }

    status = webauth_krb5_init_via_tgt(ctxt,
                                       sub_pt->proxy_data, 
                                       sub_pt->proxy_data_len,
                                       NULL);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r,
                                              status, ctxt,
                                              "webauth_krb5_init_via_tgt");
        webauth_krb5_free(ctxt);
        /* FIXME: probably need to examine errors a little more closely
         *        to determine if we should return a proxy-token error
         *        or a server-failure.
         */
        generate_errorResponse(rc, WA_PEC_PROXY_TOKEN_INVALID, msg,
                               mwk_func, 1);
        return 0;
    }

    /* now try and export a ticket */
    status = webauth_krb5_export_ticket(ctxt,
                                        (char*)sp,
                                        &ticket,
                                        &ticket_len,
                                        &ticket_expiration);

    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r,
                                              status, ctxt,
                                              "webauth_krb5_export_ticket");
        webauth_krb5_free(ctxt);
        generate_errorResponse(rc, WA_PEC_GET_CRED_FAILURE, msg, mwk_func, 1);
        return 0;
    }

    webauth_krb5_free(ctxt);

    /* now create the cred-token */
    alist = new_attr_list_er(rc, mwk_func);
    if (alist == NULL)
        return 0;

    time(&creation);

    /* expiration comes from min of ticket_expiration and proxy-token's
     * expiration.
     */
    expiration = (ticket_expiration < sub_pt->expiration) ?
        ticket_expiration : sub_pt->expiration;

    SET_TOKEN_TYPE(WA_TT_CRED);
    SET_CRED_TYPE(ct);
    SET_CRED_DATA(ticket, ticket_len);
    SET_SUBJECT(sub_pt->subject);
    SET_CREATION_TIME(creation);
    SET_EXPIRATION_TIME(expiration);

    ok = make_token_with_key_er(rc, &req_cred->u.service.st.key,
                                alist, creation,
                                (char**)&rtoken->token_data, 
                                &tlen, 1, mwk_func);
    free(ticket);
    webauth_attr_list_free(alist);
    return ok;
}

static int
handle_getTokensRequest_er(MWK_REQ_CTXT *rc, apr_xml_elem *e)
{
    apr_xml_elem *child, *tokens, *token;
    static const char *mwk_func="handle_getTokensRequest";
    const char *mid = NULL;

    MWK_REQUESTER_CREDENTIAL req_cred;
    MWK_SUBJECT_CREDENTIAL sub_cred;
    int req_cred_parsed = 0;
    int sub_cred_parsed = 0;
    int num_tokens, i;

    MWK_RETURNED_TOKEN rtokens[MAX_TOKENS_RETURNED];

    tokens = NULL;

    memset(&req_cred, 0, sizeof(req_cred));
    memset(&sub_cred, 0, sizeof(sub_cred));

    /* walk through each child element in <getTokensRequest> */
    for (child = e->first_child; child; child = child->next) {
        if (strcmp(child->name, "requesterCredential") == 0) {
            if (!parse_requesterCredential_er(rc, child, &req_cred))
                return OK; /* already logged err and generated errorResponse */
            req_cred_parsed = 1;
        } else if (strcmp(child->name, "subjectCredential") == 0) {
            if (!parse_subjectCredential_er(rc, child, &sub_cred))
                return OK; /* already logged err and generated errorResponse */
            sub_cred_parsed = 1;
        } else if (strcmp(child->name, "messageId") == 0) {
            mid = mwk_get_elem_text(rc, child, NULL);
        } else if (strcmp(child->name, "tokens") == 0) {
            tokens = child;
        } else {
            unknown_element_er(rc, mwk_func, e->name, child->name);
            return OK;
        }
    }

    /* make sure we found some tokens */
    if (tokens == NULL) {
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                               "missing <tokens> in getTokensRequest",
                               mwk_func, 1);
        return OK;
    }

    /* make sure we found requesterCredential */
    if (!req_cred_parsed) {
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                       "missing <requesterCredential> in getTokensRequest",
               
        mwk_func, 1);
        return OK;
    }

    /* make sure sub_cred looks ok if its present */
    if (sub_cred_parsed && strcmp(sub_cred.type, "proxy") != 0) {
            generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                                 "<subjectCredential> should be of type proxy",
                                 mwk_func, 1);
            return OK;
    }

    /* if req_cred is of type "service", compare command name */
    if (strcmp(req_cred.type, "service") == 0 &&
        strcmp(req_cred.u.service.rt.cmd, "getTokensRequest") != 0) {
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                               "xml command in request-token doesn't match",
                               mwk_func, 1);
        return OK;
    }


    num_tokens = 0;
    /* plow through each <token> in <tokens> */
    for (token = tokens->first_child; token; token = token->next) {
        const char *tt;

        if (strcmp(token->name, "token") != 0) {
            unknown_element_er(rc, mwk_func, tokens->name, token->name);
            return OK;
        }

        if (num_tokens == MAX_TOKENS_RETURNED) {
            generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                                   "too many tokens requested",
                                   mwk_func, 1);
            return OK;            
        }

        rtokens[num_tokens].session_key = NULL;
        rtokens[num_tokens].expires = NULL;
        rtokens[num_tokens].token_data = NULL;
        rtokens[num_tokens].id = get_attr_value_er(rc, token, "id",
                                                   0, mwk_func);

        tt = get_attr_value_er(rc, token, "type", 1, mwk_func);
        if (tt == NULL)
            return OK;

        /* make sure we found subjectCredential if requesting
         * a token type other then "sevice".
         */
        if (strcmp(tt, "service") !=0 && !sub_cred_parsed) {

            generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                       "missing <subjectCredential> in getTokensRequest",
                        mwk_func, 1);
            return OK;
        }

        if (strcmp(tt, "service") == 0) {
            if (!create_service_token_from_req_er(rc, &req_cred,
                                               &rtokens[num_tokens])) {
                return OK;
            }
        } else if (strcmp(tt, "id") == 0) {
            const char *at;
            apr_xml_elem *auth;

            auth = get_element_er(rc, token, "authenticator", 1, mwk_func);
            if (auth == NULL)
                return 0;
            at = get_attr_value_er(rc, auth, "type", 1, mwk_func);
            if (at == NULL) 
                return 0;

            if (!create_id_token_from_req_er(rc, at, 
                                             &req_cred, &sub_cred,
                                             &rtokens[num_tokens])) {
                return OK;
            }
        } else if (strcmp(tt, "proxy") == 0) {
            apr_xml_elem *proxy_type;
            const char *pt;

            proxy_type = get_element_er(rc, token, "proxyType", 1, mwk_func);
            
            if (proxy_type == NULL)
                return 0;

            pt = mwk_get_elem_text(rc, proxy_type, NULL);
            if (pt == NULL) 
                return 0;

            if (!create_proxy_token_from_req_er(rc, pt, 
                                                &req_cred, &sub_cred,
                                                &rtokens[num_tokens])) {
                return OK;
            }
        } else if (strcmp(tt, "cred") == 0) {
            if (!create_cred_token_from_req_er(rc, token,
                                               &req_cred, &sub_cred,
                                               &rtokens[num_tokens])) {
                return OK;
            }
        } else {
            char *msg = apr_psprintf(rc->r->pool, 
                                     "unknown token type: %s", tt);
            generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg,
                                   mwk_func, 1);
            return OK;
        }
        num_tokens++;
    }

    /* if we got here, we made it! */
    ap_rvputs(rc->r, "<getTokensResponse><tokens>", NULL);

    for (i = 0; i < num_tokens; i++) {
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
    }
    ap_rvputs(rc->r, "</tokens></getTokensResponse>", NULL);
    ap_rflush(rc->r);

    return OK;
}

/*
 * attempt to login. If successful, fill in both sub_cred and
 * rtokens and return 1. If unsuccessful, generate an errorResponse/log
 * and return 0.
 *
 * This is the point at which different types of authentication
 * could be plugged in, and the point at which we should create
 * all the different types of proxy-tokens we'll be needing at
 * login time.
 */

int 
mwk_do_login_er(MWK_REQ_CTXT *rc,
                MWK_LOGIN_TOKEN *lt,
                MWK_SUBJECT_CREDENTIAL *sub_cred,
                MWK_RETURNED_PROXY_TOKEN rtokens[],
                int *num_rtokens) 
{
    static const char*mwk_func = "mwk_do_login_er";
    WEBAUTH_KRB5_CTXT *ctxt;
    char *subject, *server_principal;
    int status, ok, tgt_len, len;
    time_t tgt_expiration, creation;
    void *tgt;
    MWK_PROXY_TOKEN *pt;
    WEBAUTH_ATTR_LIST *alist;

    ok = 0;

    ctxt = mwk_get_webauth_krb5_ctxt(rc->r, mwk_func);
    if (ctxt == NULL) {
        /* mwk_get_webauth_krb5_ctxt already logged error */
        return generate_errorResponse(rc, WA_PEC_SERVER_FAILURE, 
                                      "server failure", mwk_func, 0);
        return 0;
    }

    status = webauth_krb5_init_via_password(ctxt,
                                            lt->username,
                                            lt->password,
                                            rc->sconf->keytab_path,
                                            NULL,
                                            &server_principal);

    if (status == WA_ERR_LOGIN_FAILED) {
        char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                             "webauth_krb5_init_via_password");
        /* FIXME: we normally wouldn't log failures, would we? */
        generate_errorResponse(rc, WA_PEC_LOGIN_FAILED, msg, mwk_func, 1);
        goto cleanup;
    } else if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                             "webauth_krb5_init_via_password");
        generate_errorResponse(rc, WA_PEC_SERVER_FAILURE, msg, mwk_func, 1);
        goto cleanup;
    } else {
        /* copy server_principal to request pool */
        char *temp = apr_pstrdup(rc->r->pool, server_principal);
        free(server_principal);
        server_principal = temp;

    }

    /* get subject */
    status = webauth_krb5_get_principal(ctxt, &subject);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                             "webauth_krb5_get_principal");
        generate_errorResponse(rc, WA_PEC_SERVER_FAILURE, msg, mwk_func, 1);
        goto cleanup;
    } else {
        char *new_subject = apr_pstrcat(rc->r->pool, "krb5:", subject, NULL);
        free(subject);
        subject = new_subject;
    }

    /* export TGT for webkdc-proxy-token */
    status = webauth_krb5_export_tgt(ctxt, (unsigned char**)&tgt, 
                                     &tgt_len, &tgt_expiration);
    if (status != WA_ERR_NONE) {
        char *msg = mwk_webauth_error_message(rc->r, status, ctxt,
                                              "webauth_krb5_export_tgt");
        generate_errorResponse(rc, WA_PEC_SERVER_FAILURE, msg, mwk_func, 1);
        goto cleanup;
    } else {
        void *new_tgt = apr_palloc(rc->r->pool, tgt_len);
        memcpy(new_tgt, tgt, tgt_len);
        free(tgt);
        tgt = new_tgt;
    }

    /* we now have everything we need to create the webkdc-proy-token 
     * lets load up data in the sub_cred proxy token and use it
     * to create a token we'll return.
     *
     * we've already copied all this stuff into a pool, so there is no
     * need to copy again...
     */

    pt = &sub_cred->u.proxy.pt[0];

    pt->proxy_type = "krb5";
    pt->proxy_subject = server_principal;
    pt->subject = subject;
    pt->proxy_data = tgt;
    pt->proxy_data_len = tgt_len;

    /* if ProxyTopkenMaxLifetime is non-zero, use the min of it 
       and the tgt, else just use the tgt  */
    if (rc->sconf->proxy_token_max_lifetime) {
        pt->expiration = 
            (tgt_expiration < rc->sconf->proxy_token_max_lifetime) ?
            tgt_expiration : rc->sconf->proxy_token_max_lifetime;
    } else {
        pt->expiration = tgt_expiration;
    }

    time(&creation);

    alist = new_attr_list_er(rc, mwk_func);
    if (alist == NULL)
        goto cleanup;

    SET_TOKEN_TYPE(WA_TT_WEBKDC_PROXY);
    SET_PROXY_SUBJECT(pt->proxy_subject);
    SET_PROXY_TYPE(pt->proxy_type);
    SET_SUBJECT(pt->subject);
    SET_PROXY_DATA(tgt, tgt_len);
    SET_CREATION_TIME(creation);
    SET_EXPIRATION_TIME(pt->expiration);

    ok = make_token_er(rc, alist, creation,
                       (char**)&rtokens[0].token_data, &len, 1, mwk_func);
    if (ok) {
        rtokens[0].type = pt->proxy_type;
        *num_rtokens = 1;
        sub_cred->u.proxy.num_proxy_tokens = 1;
    }

    webauth_attr_list_free(alist);
    
 cleanup:        

    webauth_krb5_free(ctxt);
    return ok;

}

static int
handle_requestTokenRequest_er(MWK_REQ_CTXT *rc, apr_xml_elem *e)
{
    apr_xml_elem *child;
    static const char *mwk_func="handle_requestTokenRequest";
    char *request_token;
    MWK_REQUESTER_CREDENTIAL req_cred;
    MWK_SUBJECT_CREDENTIAL parsed_sub_cred, login_sub_cred, *sub_cred;

    MWK_REQUEST_TOKEN req_token;
    int req_cred_parsed = 0;
    int sub_cred_parsed = 0;
    int num_tokens, i;

    MWK_RETURNED_TOKEN rtoken;
    MWK_RETURNED_PROXY_TOKEN rptokens[MAX_PROXY_TOKENS_RETURNED];

    request_token = NULL;
    memset(&req_cred, 0, sizeof(req_cred));
    memset(&sub_cred, 0, sizeof(sub_cred));
    memset(&req_token, 0, sizeof(req_token));

    /* walk through each child element in <requestTokenRequest> */
    for (child = e->first_child; child; child = child->next) {
        if (strcmp(child->name, "requesterCredential") == 0) {
            if (!parse_requesterCredential_er(rc, child, &req_cred))
                return OK; /* already logged err and generated errorResponse */
            req_cred_parsed = 1;
        } else if (strcmp(child->name, "subjectCredentials") == 0) {
            if (!parse_subjectCredential_er(rc, child, &parsed_sub_cred))
                return OK; /* already logged err and generated errorResponse */
            sub_cred_parsed = 1;
        } else if (strcmp(child->name, "requestToken") == 0) {
            request_token = mwk_get_elem_text(rc, child, NULL);
        } else {
            unknown_element_er(rc, mwk_func, e->name, child->name);
            return OK;
        }
    }

    /* make sure we found requesterCredential */
    if (!req_cred_parsed) {
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                               "missing <requesterCredential>",
                               mwk_func, 1);
        return OK;
    }

    /* make sure we found subjectCredentials */
    if (!sub_cred_parsed) {
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                               "missing <subjectCredential>",
                               mwk_func, 1);
        return OK;
    }

    /* make sure req_cred is of type "service" */
    if (strcmp(req_cred.type, "service") != 0) {
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                    "must use <requesterCredential> of type 'service'",
                    mwk_func, 1);
        return OK;
    }

    /* make sure we found requestToken */
    if (request_token == NULL) {
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, 
                               "missing <requestToken>",
                               mwk_func, 1);
        return OK;
    }

    if (!parse_request_token_er(rc, request_token, 
                                &req_cred.u.service.st, &req_token, 0)) {
        return OK;
    }

    /*
     * if we have a login-token, attempt to login with it,
     * and if that succeeds, we'll get a new MWK_SUBJECT_CREDENTIAL
     * to pass around, and new proxy-tokens to set.
     *
     */
    if (strcmp(parsed_sub_cred.type, "login") == 0) {
        if (!mwk_do_login_er(rc, &parsed_sub_cred.u.lt, 
                      &login_sub_cred, rptokens, &num_tokens))
            return 0;
        sub_cred = &login_sub_cred;
    } else {
        sub_cred = &parsed_sub_cred;
    }

    /* now examine req_token to see what they asked for */
    
    if (strcmp(req_token.requested_token_type, "id") == 0) {
        if (!create_id_token_from_req_er(rc, req_token.u.subject_auth_type,
                                         &req_cred, sub_cred, &rtoken))
            return OK;
    } else if (strcmp(req_token.requested_token_type, "proxy") == 0) {
        if (!create_proxy_token_from_req_er(rc, req_token.u.proxy_type,
                                         &req_cred, sub_cred, &rtoken))
            return OK;
    } else {
        char *msg = apr_psprintf(rc->r->pool, 
                                 "unsupported requested-token-type: %s",
                                 req_token.requested_token_type);
        generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, msg,
                               mwk_func, 1);
        return OK;
    }

    /* if we got here, we made it! */
    ap_rvputs(rc->r, "<requestTokenResponse>", NULL);

    if (num_tokens) {
        ap_rvputs(rc->r, "<proxyTokens>", NULL);
        for (i = 0; i < num_tokens; i++) {
            ap_rvputs(rc->r, "<proxyToken type=\"", rptokens[i].type,">", 
                      /* don't have to quote since base64'd data */
                      rptokens[i].token_data,
                      "</proxyToken>",
                      NULL);
        }
        ap_rvputs(rc->r, "</proxyTokens>", NULL);        
    }
    /* put out return-url */
    ap_rvputs(rc->r,"<returnUrl>",
              apr_xml_quote_string(rc->r->pool, req_token.return_url, 1),
              "</returnUrl>", NULL);

    /* requesterSubject */
    ap_rvputs(rc->r,"<requesterSubject>",
              apr_xml_quote_string(rc->r->pool, req_cred.subject, 1),
              "</requesterSubject>", NULL);

    /* requestedToken, don't need to quote */
    ap_rvputs(rc->r,
              "<requestedToken>", rtoken.token_data, "</requestedToken>", 
              NULL);
    
    /* appState, need to base64-encode */
    if (req_token.app_state_len) {
        char *out_state = (char*) 
            apr_palloc(rc->r->pool, 
                       apr_base64_encode_len(req_token.app_state_len));
        apr_base64_encode(out_state, req_token.app_state,
                          req_token.app_state_len);
        /*  don't need to quote */
        ap_rvputs(rc->r,
                  "<appState>", out_state , "</appState>", 
                  NULL);
    }
    ap_rvputs(rc->r, "</getTokensResponse>", NULL);
    ap_rflush(rc->r);

    return OK;
}

static int
parse_request(MWK_REQ_CTXT *rc)
{
    int s, num_read;
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
        return generate_errorResponse(rc, WA_PEC_SERVER_FAILURE, 
                                      "server failure", mwk_func, 0);
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
            return generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, errbuff,
                                          mwk_func, 0);
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                       "mod_webkdc: %s: ap_get_client_block error", mwk_func);
            return generate_errorResponse(rc, WA_PEC_INVALID_REQUEST,
                                  "read error while parsing", mwk_func, 0);
        }
    }

    if (strcmp(xd->root->name, "getTokensRequest") == 0) {
        return handle_getTokensRequest_er(rc, xd->root);
    } else if (strcmp(xd->root->name, "requestTokenRequest") == 0) {
        return handle_requestTokenRequest_er(rc, xd->root);
    } else {
        char *m = apr_psprintf(rc->r->pool, "invalid command: %s", 
                               xd->root->name);
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webkdc: %s: %s", mwk_func, m);
        return generate_errorResponse(rc, WA_PEC_INVALID_REQUEST, m,
                                      mwk_func, 0);
    }
}

/* The sample content handler */
static int 
handler_hook(request_rec *r)
{
    MWK_REQ_CTXT rc;
    const char *req_content_type;

    rc.r = r;
    rc.sconf = (MWK_SCONF*)ap_get_module_config(r->server->module_config,
                                                &webkdc_module);

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

static int 
die(const char *message, server_rec *s)
{
    if (s) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_webkdc: fatal error: %s", message);
    }
    printf("mod_webkdc: fatal error: %s\n", message);
    exit(1);
}

/*
 * called after config has been loaded in parent process
 */
static int
mod_webkdc_init(apr_pool_t *pconf, apr_pool_t *plog,
                apr_pool_t *ptemp, server_rec *s)
{
    MWK_SCONF *sconf;
    int status;
    WEBAUTH_KEYRING *ring;

    sconf = (MWK_SCONF*)ap_get_module_config(s->module_config,
                                             &webkdc_module);

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_webkdc: initializing");

#define CHECK_DIR(field,dir,v) if (sconf->field == v) \
             die(apr_psprintf(ptemp, "directive %s must be set", dir), s)

    CHECK_DIR(keyring_path, CD_Keyring, NULL);
    CHECK_DIR(keytab_path, CD_Keytab, NULL);
    CHECK_DIR(service_token_lifetime, CD_ServiceTokenLifetime, 0);

#undef CHECK_DIR

    /* attempt to open keyring */
    status = webauth_keyring_read_file(sconf->keyring_path, &ring);
    if (status != WA_ERR_NONE) {
        die(apr_psprintf(ptemp, 
                 "mod_webkdc: webauth_keyring_read_file(%s) failed: %s (%d)",
                         sconf->keyring_path, webauth_error_message(status), 
                         status), s);
    } else {
        /* close it, and open it in child */
        webauth_keyring_free(ring);
    }

    ap_add_version_component(pconf, WEBKDC_VERSION);

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_webkdc: initialized");

    return OK;
}

/*
 * called once per-child
 */
static void
mod_webkdc_child_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t astatus;
    static const char *mwk_func="mod_webkdc_child_init";
    char errbuff[512];

    /* initialize mutexes */
#if APR_HAS_THREADS
    astatus = apr_thread_mutex_create(&g_keyring_mutex, 
                                      APR_THREAD_MUTEX_DEFAULT,
                                      s->process->pool);

    if (astatus != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "mod_webkdc: %s: apr_thread_mutex_create: %s (%d)",
                         mwk_func,
                         apr_strerror(astatus, errbuff, sizeof(errbuff)),
                         astatus);
        g_keyring_mutex = NULL;
    }
#endif

}

/*
**
**  per-server configuration structure handling
**
*/

static void *
config_server_create(apr_pool_t *p, server_rec *s)
{
    MWK_SCONF *sconf;

    sconf = (MWK_SCONF*)apr_pcalloc(p, sizeof(MWK_SCONF));

    /* init defaults */
    sconf->token_max_ttl = DF_TokenMaxTTL;
    return (void *)sconf;
}

#define MERGE_PTR(field) \
    conf->field = (oconf->field != NULL) ? oconf->field : bconf->field

#define MERGE_INT(field) \
    conf->field = oconf->field ? oconf->field : bconf->field

static void *
config_server_merge(apr_pool_t *p, void *basev, void *overv)
{
    MWK_SCONF *conf, *bconf, *oconf;

    conf = (MWK_SCONF*) apr_pcalloc(p, sizeof(MWK_SCONF));
    bconf = (MWK_SCONF*) basev;
    oconf = (MWK_SCONF*) overv;

    conf->token_max_ttl = oconf->token_max_ttl_ex ?
        oconf->token_max_ttl : bconf->token_max_ttl;

    conf->debug = oconf->debug_ex ? oconf->debug : bconf->debug;

    MERGE_PTR(keyring_path);
    MERGE_PTR(keytab_path);
    MERGE_INT(proxy_token_max_lifetime);
    MERGE_INT(service_token_lifetime);
    return (void *)conf;
}

#undef MERGE_PTR
#undef MERGE_INT

static int
seconds(const char *value, char **error_str)
{
    char temp[32];
    int mult, len;
    
    len = strlen(value);
    if (len > (sizeof(temp)-1)) {
        *error_str = "error: value too long!";
        return 0;
    }

    strcpy(temp, value);

    switch(temp[len-1]) {
        case 's': 
            mult = 1;
            break;
        case 'm':
            mult = 60;
            break;
        case 'h': 
            mult = 60*60; 
            break;
        case 'd': 
            mult = 60*60*24; 
            break;
        case 'w': 
            mult = 60*60*24*7; 
            break;
        default:
            *error_str = "error: value too long!";
            return 0;
            break;
    }
    
    temp[len-1] = '\0';
    return atoi(temp) * mult;
}

static const char *
cfg_str(cmd_parms *cmd, void *mconf, const char *arg)
{
    int e = (int)cmd->info;
    char *error_str = NULL;

    MWK_SCONF *sconf = (MWK_SCONF *)
        ap_get_module_config(cmd->server->module_config, &webkdc_module);
    
    switch (e) {
        /* server configs */
        case E_Keyring:
            sconf->keyring_path = ap_server_root_relative(cmd->pool, arg);
            break;
        case E_Keytab:
            sconf->keytab_path = ap_server_root_relative(cmd->pool, arg);
            break;
        case E_ProxyTokenMaxLifetime:
            sconf->proxy_token_max_lifetime = seconds(arg, &error_str);
            break;
        case E_TokenMaxTTL:
            sconf->token_max_ttl = seconds(arg, &error_str);
            sconf->token_max_ttl_ex = 1;
            break;
        case E_ServiceTokenLifetime:
            sconf->service_token_lifetime = seconds(arg, &error_str);
            break;
        default:
            error_str = 
                apr_psprintf(cmd->pool,
                             "Invalid value cmd->info(%d) for directive %s",
                             e,
                             cmd->directive->directive);
            break;
    }
    return error_str;
}

static const char *
cfg_flag(cmd_parms *cmd, void *mconfig, int flag)
{
    int e = (int)cmd->info;
    char *error_str = NULL;

    MWK_SCONF *sconf = (MWK_SCONF *)
        ap_get_module_config(cmd->server->module_config, &webkdc_module);
    
    switch (e) {
        /* server configs */
        case E_Debug:
            sconf->debug = flag;
            sconf->debug_ex = 1;
            break;
        default:
            error_str = 
                apr_psprintf(cmd->pool,
                             "Invalid value cmd->info(%d) for directive %s",
                             e,
                             cmd->directive->directive);
            break;

    }
    return error_str;
}


#define SSTR(dir,mconfig,help) \
  {dir, (cmd_func)cfg_str,(void*)mconfig, RSRC_CONF, TAKE1, help}

#define SFLAG(dir,mconfig,help) \
  {dir, (cmd_func)cfg_flag,(void*)mconfig, RSRC_CONF, FLAG, help}

static const command_rec cmds[] = {
    /* server/vhost */
    SSTR(CD_Keyring, E_Keyring, CM_Keyring),
    SSTR(CD_Keytab, E_Keytab,  CM_Keytab),
    SFLAG(CD_Debug, E_Debug, CM_Debug),
    SSTR(CD_TokenMaxTTL, E_TokenMaxTTL, CM_TokenMaxTTL),
    SSTR(CD_ProxyTokenMaxLifetime, E_ProxyTokenMaxLifetime, 
         CM_ProxyTokenMaxLifetime),
    SSTR(CD_ServiceTokenLifetime, E_ServiceTokenLifetime, 
         CM_ServiceTokenLifetime),
    { NULL }
};

#undef SSTR
#undef SFLAG

static void 
register_hooks(apr_pool_t *p)
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
    config_server_create,  /* create per-server config structures */
    config_server_merge,   /* merge  per-server config structures */
    cmds,                  /* table of config file commands       */
    register_hooks         /* register hooks                      */
};

