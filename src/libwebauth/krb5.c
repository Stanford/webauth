
#include "webauthp.h"

#include <stdio.h>
#include <krb5.h>
#include <netdb.h>
#include <unistd.h>

typedef struct {
    krb5_context ctx;
    krb5_ccache cc;
    krb5_principal princ;
    krb5_error_code code;
} WEBAUTH_KRB5_CTXTP;

#define WA_CRED_DEBUG 1

static char *
get_hostname()
{
    static char hostname[MAXHOSTNAMELEN+1] = {0};
    if (!hostname[0]) {
        if (gethostname(hostname, sizeof(hostname)-1) < 0) {
            return NULL;
        }
        hostname[sizeof(hostname)-1] = '\0';
    }
    return hostname;
}

int
webauth_krb5_init(WEBAUTH_KRB5_CTXT **ctxt)
{
    WEBAUTH_KRB5_CTXTP *c;

    *ctxt = NULL;
    assert(ctxt);

    c = malloc(sizeof(WEBAUTH_KRB5_CTXTP));
    if (c == NULL) {
        return WA_ERR_NO_MEM;
    }

    c->cc = NULL;
    c->princ = NULL;

    *ctxt = (WEBAUTH_KRB5_CTXT*) c;

    c->code = krb5_init_context(&c->ctx);

    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

     return WA_ERR_NONE;
}

static int
verify_tgt(WEBAUTH_KRB5_CTXTP *c, const char *keytab_path, const char *service)
{
    char *hname = get_hostname();
    krb5_principal server;
    krb5_keytab keytab;
    krb5_auth_context auth;
    krb5_data outbuf;

    if (hname == NULL) {
        return WA_ERR_GETHOSTNAME;
    }

    c->code = krb5_sname_to_principal(c->ctx, hname, service,
                                      KRB5_NT_SRV_HST, &server);

    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

    c->code = krb5_kt_resolve(c->ctx, keytab_path, &keytab);

    if (c->code != 0) {
        krb5_free_principal(c->ctx, server);
        return WA_ERR_KRB5;
    }

    auth = NULL;
    c->code = krb5_mk_req(c->ctx, &auth, 0, (char*)service, hname, 
                          NULL, c->cc, &outbuf);

    if (c->code != 0) {
        krb5_free_principal(c->ctx, server);
        return WA_ERR_KRB5;
    }

    if (auth != NULL) {
        krb5_auth_con_free(c->ctx, auth);
    }

    auth = NULL;
    c->code = krb5_rd_req(c->ctx, &auth, &outbuf, server, keytab, NULL, NULL);
    if (auth != NULL) {
        krb5_auth_con_free(c->ctx, auth);
    }
                          
    krb5_free_data_contents(c->ctx, &outbuf);
    krb5_kt_close(c->ctx, keytab);
    krb5_free_principal(c->ctx, server);

    return (c->code == 0) ? WA_ERR_NONE : WA_ERR_KRB5;
}

int
webauth_krb5_init_creds_password(WEBAUTH_KRB5_CTXT *context,
                                 const char *username,
                                 const char *password,
                                 const char *service,
                                 const char *keytab)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP*)context;
    char ccname[128];
    char *tpassword;
    krb5_creds creds;
    krb5_get_init_creds_opt opts;

    c->code = krb5_parse_name(c->ctx, username, &c->princ);

    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

   /* FIXME: is %p portable? */
#ifndef WA_CRED_DEBUG
    sprintf(ccname, "MEMORY:%p", c);
#else 
    unlink("/tmp/webauth_krb5");
    sprintf(ccname, "FILE:/tmp/webauth_krb5");
#endif
    c->code = krb5_cc_resolve(c->ctx, ccname, &c->cc);

    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

    c->code = krb5_cc_initialize(c->ctx, c->cc, c->princ);

    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

    krb5_get_init_creds_opt_init(&opts);
    krb5_get_init_creds_opt_set_forwardable(&opts, 1);
    /*krb5_get_init_creds_opt_set_tkt_life(&opts, KRB5_DEFAULT_LIFE);*/

    tpassword = strdup(password);
    if (tpassword == NULL) {
        return WA_ERR_NO_MEM;
    }

    c->code = krb5_get_init_creds_password(c->ctx,
                                           &creds,
                                           c->princ,
                                           (char*)tpassword,
                                           NULL, /* prompter */
                                           NULL, /* data */
                                           NULL, /* start_time */
                                           NULL, /* in_tkt_service */
                                           &opts);

    free(tpassword);
    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

    /* add the creds to the cache */
    c->code = krb5_cc_store_cred(c->ctx, c->cc, &creds);
    if (c->code != 0) {
        krb5_free_cred_contents(c->ctx, &creds);
        return WA_ERR_KRB5;
    }
    krb5_free_cred_contents(c->ctx, &creds);

    /* lets see if the credentials are valid */

    return verify_tgt(c, keytab, service);
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
#ifndef WA_CRED_DEBUG
        krb5_cc_destroy(c->ctx, c->cc);
#else
        krb5_cc_close(c->ctx, c->cc);
#endif
    }
    if (c->princ) {
        krb5_free_principal(c->ctx, c->princ);
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
