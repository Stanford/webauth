
/*
 * utility stuff
 */

#include "mod_webkdc.h"

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


void
mwk_log_webauth_error(request_rec *r, 
                      int status, 
                      WEBAUTH_KRB5_CTXT *ctxt,
                      const char *mwk_func,
                      const char *func)
{
    if (status == WA_ERR_KRB5 && ctxt != NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "mod_webkdc: %s: %s failed: %s (%d): %s %d",
                     mwk_func, func,
                     webauth_error_message(status), status,
                     webauth_krb5_error_message(ctxt), 
                     webauth_krb5_error_code(ctxt));
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "mod_webkdc: %s: %s failed: %s (%d)",
                     mwk_func,
                     func,
                     webauth_error_message(status), status);
    }
}
