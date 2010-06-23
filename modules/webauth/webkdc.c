/*
 * Management of service tokens and WebKDC queries.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2004, 2006, 2009, 2010
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <modules/webauth/mod_webauth.h>

/* Earlier versions of cURL don't have CURLOPT_WRITEDATA. */
#ifndef CURLOPT_WRITEDATA
# define CURLOPT_WRITEDATA CURLOPT_FILE
#endif


/*
 * make a copy of the service token into the given pool
 */
static MWA_SERVICE_TOKEN *
copy_service_token(apr_pool_t *pool,
                   MWA_SERVICE_TOKEN *orig)
{
    MWA_SERVICE_TOKEN *copy;

    if (orig == NULL)
        return NULL;

    copy = (MWA_SERVICE_TOKEN*) apr_pcalloc(pool, sizeof(MWA_SERVICE_TOKEN));

    copy->pool = pool;
    copy->expires = orig->expires;
    copy->created = orig->created;
    copy->token = apr_pstrdup(pool, orig->token);
    copy->next_renewal_attempt = orig->next_renewal_attempt;
    copy->last_renewal_attempt = orig->last_renewal_attempt;
    copy->key.type = orig->key.type;
    copy->key.data = apr_pstrmemdup(pool, orig->key.data, orig->key.length);
    copy->key.length = orig->key.length;
    copy->app_state = apr_pstrmemdup(pool, orig->app_state,
                                     orig->app_state_len);
    copy->app_state_len = orig->app_state_len;
    return copy;
}


static MWA_SERVICE_TOKEN *
new_service_token(apr_pool_t *pool,
                  int key_type, 
                  const char *kdata,
                  size_t kd_len,
                  const char *tdata,
                  size_t td_len,
                  time_t expires,
                  time_t created,
                  time_t last_renewal_attempt,
                  time_t next_renewal_attempt)
{
    MWA_SERVICE_TOKEN *token;

    token = apr_pcalloc(pool, sizeof(MWA_SERVICE_TOKEN));
    token->pool = pool;
    token->expires = expires;
    token->created = created;

    token->token = apr_pstrmemdup(pool, tdata, td_len);

    token->next_renewal_attempt = next_renewal_attempt;
    token->last_renewal_attempt = last_renewal_attempt;
    token->key.type = key_type;

    token->key.data = apr_pstrmemdup(pool, kdata, kd_len);
    token->key.length = kd_len;
    return token;
}


static MWA_SERVICE_TOKEN *
read_service_token_cache(server_rec *server,
                             MWA_SCONF *sconf, 
                             apr_pool_t *pool)
{
    MWA_SERVICE_TOKEN *token;
    apr_file_t *cache;
    apr_finfo_t finfo;
    char *buffer;
    apr_status_t astatus;
    int status;
    size_t tlen, klen;
    size_t num_read;
    int s_expires, s_token, s_lra, s_kt, s_key, s_nra, s_created;
    time_t expires, lra, nra, created;
    uint32_t key_type;
    char *tok;
    void *key;

    WEBAUTH_ATTR_LIST *alist;
    static const char *mwa_func = "mwa_read_service_token_cache";

    /* check file */
    astatus = apr_file_open(&cache, sconf->st_cache_path,
                            APR_READ|APR_FILE_NOCLEANUP,
                            APR_UREAD|APR_UWRITE,
                            pool);

    if (astatus != APR_SUCCESS) {
        if (!APR_STATUS_IS_ENOENT(astatus)) {
            mwa_log_apr_error(server, astatus, mwa_func, "apr_file_open",
                              sconf->st_cache_path, NULL);
        }
        return NULL;
    }

    astatus = apr_file_info_get(&finfo, APR_FINFO_NORM, cache);
    if (astatus != APR_SUCCESS) {
        mwa_log_apr_error(server, astatus, mwa_func, "apr_file_info_get",
                          sconf->st_cache_path, NULL);
        apr_file_close(cache);
        return NULL;
    }

    buffer = apr_palloc(pool, finfo.size);

    astatus = apr_file_read_full(cache, buffer, finfo.size, &num_read);
    apr_file_close(cache);

    if (astatus != APR_SUCCESS) {
        mwa_log_apr_error(server, astatus, mwa_func, "apr_file_read_full",
                          sconf->st_cache_path, NULL);
        return NULL;
    }

    if (finfo.size == 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, server, 
                     "mod_webauth: %s: service token cache is zero length: %s",
                     mwa_func, sconf->st_cache_path);
        return NULL;
    }

    status = webauth_attrs_decode(buffer, finfo.size, &alist);

    if (status != WA_ERR_NONE) {
        mwa_log_webauth_error(server, status, "mwa_func", 
                              "webauth_attrs_decode", 
                              sconf->st_cache_path);
        return NULL;
    }

    s_expires = webauth_attr_list_get_time(alist, "expires", &expires, 
                                           WA_F_FMT_STR);

    s_created = webauth_attr_list_get_time(alist, "created", &created,
                                           WA_F_FMT_STR);

    s_token = webauth_attr_list_get_str(alist, "token", &tok, &tlen,
                                        WA_F_NONE);
    s_lra = webauth_attr_list_get_time(alist, "last_renewal_attempt", 
                                       &lra, WA_F_FMT_STR);
    s_nra = webauth_attr_list_get_time(alist, "next_renewal_attempt", 
                                       &nra, WA_F_FMT_STR);
    s_kt = webauth_attr_list_get_uint32(alist, "key_type", &key_type,
                                        WA_F_FMT_STR);
    s_key = webauth_attr_list_get(alist, "key", &key, &klen, WA_F_FMT_HEX);

    if ((s_expires != WA_ERR_NONE) || (s_token != WA_ERR_NONE) ||
        (s_lra != WA_ERR_NONE) || (s_kt != WA_ERR_NONE) ||
        (s_nra != WA_ERR_NONE) || (s_created != WA_ERR_NONE) ||
        (s_key != WA_ERR_NONE)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
                     "mod_webauth: %s: attr_list_get failed for: %s%s%s%s%s%s%s",
                     mwa_func,
                     (s_expires != WA_ERR_NONE) ? "expires" : "",
                     (s_created != WA_ERR_NONE) ? "created" : "",
                     (s_token != WA_ERR_NONE) ? "token" : "",
                     (s_lra != WA_ERR_NONE) ? "last_renewal_attempt" : "",
                     (s_nra != WA_ERR_NONE) ? "next_renewal_attempt" : "",
                     (s_kt != WA_ERR_NONE) ? "key_type" : "",
                     (s_key != WA_ERR_NONE) ? "key" : "");
        return NULL;
    }

    token = new_service_token(pool, key_type, key, klen, tok, tlen, expires,
                              created, lra, nra);
    webauth_attr_list_free(alist);
    return token;
}


static int
write_service_token_cache(server_rec *server, MWA_SCONF *sconf,
                          apr_pool_t *pool, MWA_SERVICE_TOKEN *token)
{
    apr_file_t *cache;
    char *buffer;
    apr_status_t astatus;
    int status, ok;
    size_t buff_len, ebuff_len;
    size_t bytes_written;
    char *templ;
    WEBAUTH_ATTR_LIST *alist;
    static const char *mwa_func = "write_service_token_cache";

    /* store new cache in a temp file, and move over if everything ok */
    templ = apr_pstrcat(pool, sconf->st_cache_path, "XXXXXX", NULL);
    astatus = apr_file_mktemp(&cache, templ, 
                              APR_WRITE|APR_CREATE|
                              APR_TRUNCATE |APR_FILE_NOCLEANUP,
                              pool);

    if (astatus != APR_SUCCESS) {
        mwa_log_apr_error(server, astatus, mwa_func, "apr_file_mktemp",
                          templ, NULL);
        return 0;
    }

    ok = 0;

    alist = webauth_attr_list_new(10);

    webauth_attr_list_add_str(alist, "token", (char *) token->token, 0,
                              WA_F_NONE);

    webauth_attr_list_add_uint32(alist, "key_type", 
                                 token->key.type, WA_F_FMT_STR);

    webauth_attr_list_add_time(alist, "expires", 
                                 token->expires, WA_F_FMT_STR);

    webauth_attr_list_add_time(alist, "created", 
                                 token->created, WA_F_FMT_STR);

    webauth_attr_list_add_time(alist, "last_renewal_attempt", 
                                 token->last_renewal_attempt, WA_F_FMT_STR);

    webauth_attr_list_add_time(alist, "next_renewal_attempt", 
                                 token->next_renewal_attempt, WA_F_FMT_STR);

    webauth_attr_list_add(alist, "key", token->key.data,
                          token->key.length, WA_F_FMT_HEX);

    buff_len = webauth_attrs_encoded_length(alist);
    buffer = apr_palloc(pool, buff_len);

    status = webauth_attrs_encode(alist, buffer, &ebuff_len, buff_len);
    webauth_attr_list_free(alist);

    if (status != WA_ERR_NONE) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server,
                     "mod_webauth: %s: webauth_attrs_encode failed: %s (%d)",
                     mwa_func, webauth_error_message(status), status);
        goto cleanup;
    }

    astatus = apr_file_write_full(cache, buffer, ebuff_len, &bytes_written);

    if (status != APR_SUCCESS) {
        mwa_log_apr_error(server, astatus, mwa_func, "apr_file_write_file",
                      templ, NULL);
        goto cleanup;
    }

    ok = 1;

 cleanup:

    /* always close */
    astatus = apr_file_close(cache);

    if (astatus != APR_SUCCESS) {
        ok = 0;
        mwa_log_apr_error(server, astatus, mwa_func, "apr_file_close",
                      templ, NULL);
    }

    /* if we are ok, set perms on the temp file */
    if (ok) {
        astatus = apr_file_perms_set(templ, APR_UREAD|APR_UWRITE);

        if (astatus != APR_SUCCESS && astatus != APR_ENOTIMPL) {
            mwa_log_apr_error(server, astatus, mwa_func, "apr_file_perms_set",
                          templ, NULL);
            /* not ok anymore */
            ok = 0;
        }
    }

    /* if we are ok at this point, rename, otherwise remove */
    if (ok) {
        astatus = apr_file_rename(templ, sconf->st_cache_path, pool);
        if (astatus != APR_SUCCESS) {
            mwa_log_apr_error(server, astatus, mwa_func, "apr_file_rename",
                              templ, sconf->st_cache_path);
            ok = 0;
        }
    } else {
        /* not ok, nuke it */
        astatus = apr_file_remove(templ, pool);
        if (astatus != APR_SUCCESS) {        
            mwa_log_apr_error(server, astatus, mwa_func, "apr_file_rename",
                              templ, sconf->st_cache_path);
        }
    }

    return ok;
}


#define CHUNK_SIZE 4096

/*
 *
 */
static void init_string(MWA_STRING *string, apr_pool_t *pool)
{
    memset(string, 0, sizeof(MWA_STRING));
    string->pool = pool;
}


/*
 * given an MWA_STRING, append some new data to it.
 */
static void
append_string(MWA_STRING *string, const char *in_data, size_t in_size)
{
    size_t needed_size;

    if (in_size == 0)
        in_size = strlen(in_data);

    needed_size = string->size + in_size;

    if (string->data == NULL || needed_size > string->capacity) {
        char *new_data;
        while (string->capacity < needed_size+1)
            string->capacity += CHUNK_SIZE;

        new_data = apr_palloc(string->pool, string->capacity);

        if (string->data != NULL) {
            memcpy(new_data, string->data, string->size);
        } 
        /* don't have to free existing data since it from a pool */
        string->data = new_data;
    }
    memcpy(string->data+string->size, in_data, in_size);
    string->size = needed_size;
    /* always null-terminate, we have space becase of the +1 above */
    string->data[string->size] = '\0';
}


/*
 * gather up the POST data as it comes back from webkdc
 */
static size_t
post_gather(char *in_data, size_t size, size_t nmemb, void *string)
{
    size_t real_size = size * nmemb;

    append_string(string, in_data, real_size);
    return real_size;
}


/*
 * post some xml to the webkdc and return response
 *
 * FIXME: need to think about retry/timeout policy
 */
static char *
post_to_webkdc(char *post_data, size_t post_data_len, 
               server_rec *server, MWA_SCONF *sconf,
               apr_pool_t *pool)
{
    CURL *curl;
    CURLcode code;
    char curl_error_buff[CURL_ERROR_SIZE+1];
    struct curl_slist *headers = NULL;
    MWA_STRING string;

    if (post_data_len == 0)
        post_data_len = strlen(post_data);

    curl = curl_easy_init();

    if (curl == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server,
                     "mod_webauth: post_to_webkdc: curl_easy_init failed");
        return NULL;
    }

    curl_easy_setopt(curl, CURLOPT_URL, sconf->webkdc_url);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
#ifdef CURLOPT_NOSIGNAL
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    /* FIXME: probably need directives for these */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 45);
#endif
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_error_buff);

    if (sconf->webkdc_cert_file) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, sconf->webkdc_cert_file);
    }

    if (!sconf->webkdc_cert_check) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, server,
                     "mod_webauth: turning off WebKDC cert checking! "
                     "this should only be done during testing/development");
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, post_gather);

    /* don't pre-allocate in case our write function never gets called */
    init_string(&string, pool);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &string);
    headers = curl_slist_append(headers, "Content-Type: text/xml");
 
    /* data to post */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
 
    /* set the size of the postfields data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, post_data_len);
 
    /* pass our list of custom made headers */
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
 
    curl_error_buff[0] = '\0';
    code = curl_easy_perform(curl); /* post away! */
 
    curl_slist_free_all(headers); /* free the header list */

    if (code != CURLE_OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server,
                     "mod_webauth: curl_easy_perform: error(%d): %s",
                     code, curl_error_buff);
        return NULL;
    }
    /* null-terminate return data */
    if (string.data) {
        string.data[string.size] = '\0';
    }
    curl_easy_cleanup(curl);
    return string.data;
}


/*
 * concat all the text pieces together and return data
 */
static const char *
get_elem_text(apr_pool_t *pool, apr_xml_elem *e, const char *def)
{
    if (e->first_cdata.first &&
        e->first_cdata.first->text) {
        apr_text *t;
        MWA_STRING string;
        init_string(&string, pool);
        for (t = e->first_cdata.first; t != NULL; t = t->next) {
            append_string(&string, t->text, 0);
        }
        return string.data;
    } else {
        return def;
    }
}


/*
 * parse and log errorResponse from WebKDC
 */
static void
log_error_response(apr_xml_elem *e,
                   const char *mwa_func,
                   server_rec *server,
                   apr_pool_t *pool)
{
    apr_xml_elem *sib;
    const char *error_code = "(no error_code)";
    const char *error_message = "(no error message)";

    for (sib = e->first_child; sib; sib = sib->next) {
        if (strcmp(sib->name, "errorCode") == 0) {
            error_code = get_elem_text(pool, sib, error_code);
        } else if (strcmp(sib->name, "errorMessage") == 0) {
            error_message = get_elem_text(pool, sib, error_message);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, server, 
                         "mod_webauth: log_error_response: "
                         "ignoring unknown element in <errorResponse>: <%s>",
                         sib->name);
        }
    }
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
                 "mod_webauth: %s: errorResponse from webkdc: errorCode(%s) "
                 "errorMessage(%s)",
                 mwa_func, error_code, error_message);

}


static MWA_SERVICE_TOKEN *
parse_service_token_response(apr_xml_doc *xd,
                             server_rec *server,
                             apr_pool_t *pool,
                             time_t curr)
{
    MWA_SERVICE_TOKEN *st;
    apr_xml_elem *e, *sib;
    size_t bskey_len;
    char *bskey;
    time_t first_renewal_attempt, expiration;
    static const char *mwa_func = "parse_service_token_response";
    const char *expires, *session_key, *token_data;
    
    e = xd->root;

    if (strcmp(e->name, "errorResponse") == 0) {
        log_error_response(e, mwa_func, server, pool);
        return NULL;
    } else if (strcmp(e->name, "getTokensResponse") != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
                     "mod_webauth: %s: unknown response(%s)", 
                     mwa_func, e->name);
        return NULL;
    }

    /* parse it already */
    e = e->first_child;
    if (!e || strcmp(e->name, "tokens") != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
                     "mod_webauth: %s: can't find <tokens>", 
                     mwa_func);
        return NULL;
    }

    e = e->first_child;
    if (!e || strcmp(e->name, "token") != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
                     "mod_webauth: %s: can't find <token>", 
                     mwa_func);
        return NULL;
    }

    session_key = expires = token_data = NULL;

    for (sib = e->first_child; sib; sib = sib->next) {
        if (strcmp(sib->name, "sessionKey") == 0) {
            session_key = get_elem_text(pool, sib, NULL);
        } else if (strcmp(sib->name, "expires") == 0) {
            expires = get_elem_text(pool, sib, NULL);
        } else if (strcmp(sib->name, "tokenData") == 0) {
            token_data = get_elem_text(pool, sib, NULL);
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
                         "mod_webauth: %s: "
                         "ignoring unknown element in <token>: <%s>",
                         mwa_func, sib->name);
        }
    }

    if ((session_key == NULL) || (expires == NULL) || (token_data == NULL)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
                     "mod_webauth: %s: "
                     "missing %s%s%s",
                     mwa_func, 
                     session_key == NULL ? "<sessionKey> " : "",
                     expires == NULL ? "<expires> " : "",
                     token_data == NULL ? "<tokenData> " : "");
        return NULL;
    }

    bskey = apr_palloc(pool, apr_base64_decode_len(session_key));
    bskey_len = apr_base64_decode(bskey, session_key);

    /* 
     * FIXME: initial next_renewal_attempt time is hardcoded to when the token
     * has reached 90% of its lifetime. Might want to make this a config
     * option at some point (though no good reason I can think of to
     * right now.
     */

    expiration = (time_t) atoi(expires);

    first_renewal_attempt = 
        curr + ((expiration - curr) * START_RENEWAL_ATTEMPT_PERCENT);

    st = new_service_token(pool,
                           WA_AES_KEY, /* FIXME: hardcoded for now */
                           bskey,
                           bskey_len,
                           token_data,
                           strlen(token_data),
                           expiration,
                           curr,
                           0,
                           first_renewal_attempt);
    return st;
}


/*
 * request a service token from the WebKDC
 */
static MWA_SERVICE_TOKEN *
request_service_token(server_rec *server, 
                      MWA_SCONF *sconf,
                      apr_pool_t *pool,
                      time_t curr)
{
    apr_xml_parser *xp;
    apr_xml_doc *xd;
    char *xml_request, *xml_response;
    const char *bk5_req;
    static const char *mwa_func = "request_service_token";
    apr_status_t astatus;
    MWA_CRED_INTERFACE *mci;

    /* FIXME: this is currently hardcoded to krb5, but should be a directive */
    mci = mwa_find_cred_interface(server, "krb5");
    if (mci == NULL) 
        return NULL;

    bk5_req = mci->webkdc_credential(server, sconf, pool);

    if (bk5_req == NULL)
        return NULL;

    xml_request = apr_pstrcat(pool, 
                              "<getTokensRequest>"
                              "<requesterCredential type='krb5'>",
                              bk5_req,
                              "</requesterCredential>"
                              "<tokens><token type='service'/></tokens>"
                              "</getTokensRequest>",
                              NULL);

    if (sconf->debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, 
                     "mod_webauth: xml_request(%s)", xml_request);
    }

    xml_response = post_to_webkdc(xml_request, 0, server, sconf, pool);

    if (xml_response == NULL)
        return 0;

    if (sconf->debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, 
                     "mod_webauth: xml_response(%s)", xml_response);
    }
    
    xp = apr_xml_parser_create(pool);
    if (xp == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
                     "mod_webauth: %s: apr_xml_parser_create failed", 
                     mwa_func);
        return 0;
    }

    astatus = apr_xml_parser_feed(xp, xml_response, strlen(xml_response));
    if (astatus == APR_SUCCESS) {
        astatus = apr_xml_parser_done(xp, &xd);
    }

    if (astatus != APR_SUCCESS) {
        char errbuff[1024];
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
                     "mod_webauth: %s: "
                     "apr_xml_parser_{feed,done} failed: %s (%d)", 
                     mwa_func,
                     apr_xml_parser_geterror(xp, errbuff, sizeof(errbuff)),
                     astatus);
        return 0;
    }

    return parse_service_token_response(xd, server, pool, curr);
}


/*
 * generate our app-state blob once and re-use it
 */
static void
set_app_state(server_rec *server, MWA_SCONF *sconf,
              MWA_SERVICE_TOKEN *token, time_t curr)
{
    WEBAUTH_ATTR_LIST *alist;
    size_t tlen, olen;
    int status;
    void *as;

    status = WA_ERR_NONE;

    token->app_state = NULL;
    token->app_state_len = 0;   

    alist = webauth_attr_list_new(10);

    if (alist == NULL) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, server,
                     "mod_webauth: set_app_state: "
                     "webauth_attr_list_new failed");
        return;
    }

    webauth_attr_list_add_str(alist, WA_TK_TOKEN_TYPE, WA_TT_APP, 0, 
                              WA_F_NONE);
    webauth_attr_list_add(alist, WA_TK_SESSION_KEY, 
                          token->key.data, token->key.length, WA_F_NONE);
    webauth_attr_list_add_time(alist, WA_TK_EXPIRATION_TIME,
                               token->expires, WA_F_NONE);

    tlen = webauth_token_encoded_length(alist);

    as = (char*)apr_palloc(token->pool, tlen);

    if (sconf->ring == NULL)
        return;

    status = webauth_token_create(alist, curr, as, &olen, tlen, sconf->ring);

    webauth_attr_list_free(alist);

    if (status != WA_ERR_NONE) {
        mwa_log_webauth_error(server, status, "set_app_state",
                              "webauth_token_create", NULL);
    } else {
        token->app_state = as;
        token->app_state_len = tlen;
    }
    return;
}


/*
 * create a pool for the service token and copy the new 
 * token into it. If the old_service_token is set, then destroy
 * its pool.
 */
static void
set_service_token(MWA_SERVICE_TOKEN *new_token,
                  MWA_SCONF *sconf)
{
    apr_pool_t *p;

    if (sconf->service_token)
        apr_pool_destroy(sconf->service_token->pool);
    apr_pool_create(&p, NULL);
    sconf->service_token = copy_service_token(p, new_token);
    if (sconf->debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                     "mod_webauth: setting service token");
    }

}


/*
 * this function returns a service-token to use.
 * 
 * it looks in memory first, then the service token cache, then makes
 * a request if all else fails.
 *
 * it also does housekeeping on the service token, such as attempting
 * to request a new one while the current one is still active but nearing
 * expiration.
 *
 */
MWA_SERVICE_TOKEN *
mwa_get_service_token(server_rec *server, MWA_SCONF *sconf, 
                      apr_pool_t *pool, int local_cache_only)
{
    MWA_SERVICE_TOKEN *token;
    time_t curr = time(NULL); 
    static const char *mwa_func = "mwa_get_service_token";
    apr_thread_mutex_lock(sconf->mutex); /****** LOCKING! ************/

    if (sconf->service_token != NULL) {
        /* return the current one, unless we should attempt a renewal */
        if (sconf->service_token->next_renewal_attempt > curr) {
            token = copy_service_token(pool, sconf->service_token);
            if (sconf->debug) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server,
                             "mod_webauth: %s: using cached service token",
                             mwa_func);
            }
            goto done;
        }
        /* else lets force a re-read, and maybe force a re-request */
    }

    /* check file first to see if there is a (newer) token */
    token = read_service_token_cache(server, sconf, pool);

    if (token != NULL) {

        if (sconf->debug) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server,
                         "mod_webauth: %s: read service token from: %s",
                         mwa_func, sconf->st_cache_path);
        }

        /* see if we (still) need to do a re-request or not,
         * someone might have already.
         */
        if (token->next_renewal_attempt > curr) {
            /* app state is generated on read so it always uses
               the current keying */
            set_app_state(server, sconf, token, curr);
            /* copy into its own pool for future use */
            set_service_token(token, sconf);
            goto done;
        }
    }

    /* still no token, or we are renewing our current one */
    if (local_cache_only)
        goto done;

    token = request_service_token(server, sconf, pool, curr);

    if (token == NULL ) {

        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server,
                     "mod_webauth: %s: couldn't get new service "
                     "token from webkdc",
                     mwa_func);

        /* couldn't get a new one, lets update renewal_attempt times 
         * if we have a current token.
         */
        if (sconf->service_token != NULL) {

            /* update {last,next}_renewal_attempt */
            sconf->service_token->last_renewal_attempt = curr;
            sconf->service_token->next_renewal_attempt = 
                curr+TOKEN_RETRY_INTERVAL;
            write_service_token_cache(server, sconf, pool,
                                      sconf->service_token);
        }
    } else {

        if (sconf->debug) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server,
                         "mod_webauth: %s: got new service token from webkdc",
                         mwa_func);
        }

        /* got a new one, lets right it out*/
        write_service_token_cache(server, sconf, pool, token);
        set_app_state(server, sconf, token, curr);
        set_service_token(token, sconf);
        goto done;
    }

 done:

    apr_thread_mutex_unlock(sconf->mutex); /****** UNLOCKING! ************/

    if (token == NULL && !local_cache_only) {
        /* really complain! */
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, server,
                     "mod_webauth: mwa_get_service_token FAILD!!");
    }
    return token;
}


static char *
make_request_token(MWA_REQ_CTXT *rc, MWA_SERVICE_TOKEN *st, const char *cmd)
{
    WEBAUTH_ATTR_LIST *alist;
    char *token, *btoken;
    size_t tlen, olen;
    int status;
    time_t curr = time(NULL);
    const char *mwa_func = "make_request_token";

    alist = webauth_attr_list_new(10);
    if (alist == NULL) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, rc->r->server,
                     "mod_webauth: %s: webauth_attr_list_new failed",
                     mwa_func);
        return NULL;
    }

    SET_TOKEN_TYPE(WA_TT_REQUEST);
    SET_CREATION_TIME(curr);
    SET_COMMAND(cmd);

    tlen = webauth_token_encoded_length(alist);
    token = apr_palloc(rc->r->pool, tlen);

    status = webauth_token_create_with_key(alist, curr, token, &olen, tlen,
                                           &st->key);
    webauth_attr_list_free(alist);

    if (status != WA_ERR_NONE) {
        mwa_log_webauth_error(rc->r->server, status, mwa_func,
                              "webauth_token_create_with_key", NULL);
        return NULL;
    }

    btoken = apr_palloc(rc->r->pool, apr_base64_encode_len(olen));
    apr_base64_encode(btoken, token, olen);
    return btoken;
}


static int
parse_get_creds_response(apr_xml_doc *xd,
                         MWA_REQ_CTXT *rc,
                         MWA_SERVICE_TOKEN *st,
                         apr_array_header_t **acquired_creds)
{
    apr_xml_elem *e, *tokens, *token;
    static const char *mwa_func = "parse_service_token_response";
    char *token_data;
    MWA_CRED_TOKEN *ct;
    
    e = xd->root;

    if (strcmp(e->name, "errorResponse") == 0) {
        log_error_response(e, mwa_func, rc->r->server, rc->r->pool);
        return 0;
    } else if (strcmp(e->name, "getTokensResponse") != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server, 
                     "mod_webauth: %s: unknown response(%s)", 
                     mwa_func, e->name);
        return 0;
    }

    /* parse it already */
    tokens = e->first_child;
    if (!tokens || strcmp(tokens->name, "tokens") != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server, 
                     "mod_webauth: %s: can't find <tokens>", 
                     mwa_func);
        return 0;
    }

    for (token = tokens->first_child; token; token = token->next) {
        if (!token || strcmp(token->name, "token") != 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server, 
                         "mod_webauth: %s: "
                         "ignoring unknown element in <tokens>: <%s>",
                         mwa_func, token->name);
            continue;
        }

        token_data = NULL;

        for (e = token->first_child; e; e = e->next) {
            if (strcmp(e->name, "tokenData") == 0) {
                token_data = (char*)get_elem_text(rc->r->pool, e, NULL);
            } else {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server, 
                             "mod_webauth: %s: "
                             "ignoring unknown element in <token>: <%s>",
                             mwa_func, e->name);
            }
        }

        if (token_data == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server, 
                         "mod_webauth: %s: "
                         "missing <tokenData>",
                         mwa_func);
            return 0;
        }

        /* take token_data, parse it, expecting a cred-token */
        ct = mwa_parse_cred_token(token_data, NULL, &st->key, rc);
        if (ct != NULL) {
            MWA_CRED_TOKEN **nct;
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server, 
                         "mod_webauth: %s: "
                         "parsed %s %s",
                         mwa_func, ct->cred_type, ct->cred_server);

            if (*acquired_creds == NULL) 
                *acquired_creds = apr_array_make(rc->r->pool, 2,
                                                 sizeof(MWA_CRED_TOKEN*));
            nct = apr_array_push(*acquired_creds);
            *nct = ct;
        }
    }
    return 1;
}


/*
 * request a service token from the WebKDC
 */
int
mwa_get_creds_from_webkdc(MWA_REQ_CTXT *rc,
                          MWA_PROXY_TOKEN *pt,
                          MWA_WACRED *creds,
                          size_t num_creds,
                          apr_array_header_t **acquired_creds)
{
    apr_xml_parser *xp;
    apr_xml_doc *xd;
    char *xml_request, *xml_response, *b64_pt;
    size_t i;
    static const char *mwa_func = "mwa_get_creds_from_webkdc";
    apr_status_t astatus;
    MWA_SERVICE_TOKEN *st;
    MWA_STRING cred_tokens;
    char *request_token;

    /* get service token first */
    st = mwa_get_service_token(rc->r->server, rc->sconf, rc->r->pool, 0);

    if (st == NULL)
        return 0;

    /* make a new request-token */
    request_token = make_request_token(rc, st, "getTokensRequest");
    if (request_token == NULL)
        return 0;

    /* now build up all the cred tokens we need */
    init_string(&cred_tokens, rc->r->pool);

    for (i = 0; i < num_creds; i++) {
        char *id = apr_psprintf(rc->r->pool, "%d", i);
        append_string(&cred_tokens,
                      apr_pstrcat(rc->r->pool,
                                  "<token type='cred' id='",id,"'>",
                                  "<credentialType>",
                                  apr_xml_quote_string(rc->r->pool,
                                                       creds[i].type, 0),
                                  "</credentialType>",
                                  "<serverPrincipal>",
                                  apr_xml_quote_string(rc->r->pool,
                                                       creds[i].service, 0),
                                  "</serverPrincipal>",
                                  "</token>",
                                  NULL),
                      0);
    }

    /* base64 encode the webkdc-proxy-token */
    b64_pt = (char*) apr_palloc(rc->r->pool, 
                                apr_base64_encode_len(pt->wpt_len));
    apr_base64_encode(b64_pt, pt->wpt, pt->wpt_len);

    /* build the actual request */
    xml_request = apr_pstrcat(rc->r->pool, 
                              "<getTokensRequest>"
                              "<requesterCredential type='service'>",
                              st->token, /* b64'd, don't need to quote */
                              "</requesterCredential>"
                              "<subjectCredential type='proxy'>",
                              "<proxyToken>",
                              b64_pt, /* b64'd, don't need to quote */
                              "</proxyToken>",
                              "</subjectCredential>",
                              "<requestToken>",
                              request_token,
                              "</requestToken>",
                              "<tokens>",
                              cred_tokens.data,
                              "</tokens>"
                              "</getTokensRequest>",
                              NULL);

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server, 
                 "mod_webauth: xml_request(%s)", xml_request);


    xml_response = post_to_webkdc(xml_request, 0, 
                                  rc->r->server, rc->sconf, rc->r->pool);

    if (xml_response == NULL)
        return 0;

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server, 
                 "mod_webauth: xml_response(%s)", xml_response);

    
    xp = apr_xml_parser_create(rc->r->pool);
    if (xp == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server, 
                     "mod_webauth: %s: apr_xml_parser_create failed", 
                     mwa_func);
        return 0;
    }

    astatus = apr_xml_parser_feed(xp, xml_response, strlen(xml_response));
    if (astatus == APR_SUCCESS) {
        astatus = apr_xml_parser_done(xp, &xd);
    }

    if (astatus != APR_SUCCESS) {
        char errbuff[1024];
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server, 
                     "mod_webauth: %s: "
                     "apr_xml_parser_{feed,done} failed: %s (%d)", 
                     mwa_func,
                     apr_xml_parser_geterror(xp, errbuff, sizeof(errbuff)),
                     astatus);
        return 0;
    }

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server, 
                 "mod_webauth: xml doc root(%s)", xd->root->name);

    return parse_get_creds_response(xd, rc, st, acquired_creds);
}
