
#include "webauthp.h"

#include <stdio.h>
#include <krb5.h>

typedef struct {
    krb5_context ctx;
    krb5_ccache cc;
    krb5_error_code code;
} WEBAUTH_KRB5_CTXTP;

int
webauth_krb5_init(WEBAUTH_KRB5_CTXT **ctxt)
{
    WEBAUTH_KRB5_CTXTP *c;
    char ccname[128];

    *ctxt = NULL;
    assert(ctxt);
    c = malloc(sizeof(WEBAUTH_KRB5_CTXTP));
    if (c == NULL) {
        return WA_ERR_NO_MEM;
    }

    c->cc = NULL;

    *ctxt = (WEBAUTH_KRB5_CTXT*) c;

    c->code = krb5_init_context(&c->ctx);

    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

    /* FIXME: is %p portable? */
    sprintf(ccname, "MEMORY:%p", c);
    c->code = krb5_cc_resolve(c->ctx, ccname, &c->cc);

    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

    return WA_ERR_NONE;
}

int
webauth_krb5_init_creds_password(WEBAUTH_KRB5_CTXTP *ctxt,
                                 char *username,
                                 char *password,
                                 char *keytab)
{
    return WA_ERR_NONE;
}

int
webauth_krb5_get_tgt(WEBAUTH_KRB5_CTXTP *context, void **data, int *len)
{
    return WA_ERR_NONE;
}

int
webauth_krb5_free(WEBAUTH_KRB5_CTXT *context)
{    
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP*)context;
    if (c->cc) {
        krb5_cc_destroy(c->ctx, c->cc);
        krb5_cc_close(c->ctx, c->cc);
    }
    krb5_free_context(c->ctx);
    free(context);
    return WA_ERR_NONE;
}

int
webauth_krb5_set_tgt(WEBAUTH_KRB5_CTXTP *context, void *data, int len)
{
    return WA_ERR_NONE;
}

int
webauth_krb5_set_ticket(WEBAUTH_KRB5_CTXTP *context, void *data, int len)
{
    return WA_ERR_NONE;
}

int
webauth_krb5_init_creds_keytab(WEBAUTH_KRB5_CTXTP *context, char *path)
{
    return WA_ERR_NONE;
}

int
webauth_krb5_get_ticket(WEBAUTH_KRB5_CTXTP *context,
                        char *service, void **data, int *len)
{
    return WA_ERR_NONE;
}
