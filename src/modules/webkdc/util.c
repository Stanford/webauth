
/*
 * utility stuff
 */

#include "mod_webkdc.h"


#define CHUNK_SIZE 4096

/*
 *
 */
void 
mwk_init_string(MWK_STRING *string, apr_pool_t *pool)
{
    memset(string, 0, sizeof(MWK_STRING));
    string->pool = pool;
}

/*
 * given an MWA_STRING, append some new data to it.
 */
void 
mwk_append_string(MWK_STRING *string, const char *in_data, int in_size)
{
    int needed_size;

    if (in_size == 0)
        in_size = strlen(in_data);

    needed_size = string->size+in_size;

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
}


/*
 * concat all the text pieces together and return data 
 */
char *
mwk_get_elem_text(MWK_REQ_CTXT *rc, apr_xml_elem *e, char *def)
{
    if (e->first_cdata.first &&
        e->first_cdata.first->text) {
        apr_text *t;
        MWK_STRING string;
        mwk_init_string(&string, rc->r->pool);
        for (t = e->first_cdata.first; t != NULL; t = t->next) {
            mwk_append_string(&string, t->text, 0);
        }
        return string.data;
    } else {
        return def;
    }
}

/*
 * get a required char* attr from a token, with logging if not present.
 * returns value or NULL on error,
 */
char *
mwk_get_str_attr(WEBAUTH_ATTR_LIST *alist, 
                 const char *name, 
                 request_rec *r, 
                 const char *func,
                 int *vlen)
{
    int status, i;

    status = webauth_attr_list_find(alist, name, &i);
    if (i == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "mod_webkdc: %s: can't find attr(%s) in attr list",
                     func, name);
        return NULL;
    }
    if (vlen) 
        *vlen = alist->attrs[i].length;

    return (char*)alist->attrs[i].value;
}

/*
 * get a WEBAUTH_KRB5_CTXT
 */
WEBAUTH_KRB5_CTXT *
mwk_get_webauth_krb5_ctxt(request_rec *r, const char *mwk_func)
{
    WEBAUTH_KRB5_CTXT *ctxt;
    int status;

    status = webauth_krb5_new(&ctxt);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(r, status, ctxt, mwk_func, "webauth_krb5_new");
        if (status == WA_ERR_KRB5)
            webauth_krb5_free(ctxt);
        return NULL;
    }
    return ctxt;
}


char *
mwk_webauth_error_message(request_rec *r, 
                          int status, 
                          WEBAUTH_KRB5_CTXT *ctxt,
                          const char *webauth_func)
{
    if (status == WA_ERR_KRB5 && ctxt != NULL) {
        return apr_psprintf(r->pool,
                            "%s failed: %s (%d): %s %d",
                            webauth_func,
                            webauth_error_message(status), status,
                            webauth_krb5_error_message(ctxt), 
                            webauth_krb5_error_code(ctxt));
    } else {
        return apr_psprintf(r->pool,
                            "%s failed: %s (%d)",
                            webauth_func,
                            webauth_error_message(status), status);
    }
}

void
mwk_log_webauth_error(request_rec *r, 
                      int status, 
                      WEBAUTH_KRB5_CTXT *ctxt,
                      const char *mwk_func,
                      const char *func)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                 "mod_webkdc: %s: %s",
                 mwk_func, 
                 mwk_webauth_error_message(r, status, ctxt, func));
}
