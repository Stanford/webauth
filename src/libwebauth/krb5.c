
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

/*#define WA_CRED_DEBUG 1 */

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


/* these names are kept to a minimum since encoded creds end up
   in cookies,etc */

#define CR_ADDRTYPE "A%d"
#define CR_ADDRCONT "a%d"
#define CR_CLIENT "c"
#define CR_AUTHDATATYPE "D%d"
#define CR_AUTHDATACONT "d%d"
#define CR_TICKETFLAGS "f"
#define CR_ISSKEY "i"
#define CR_SERVER "s"
#define CR_KEYBLOCK_CONTENTS "k"
#define CR_KEYBLOCK_ENCTYPE "K"
#define CR_NUMADDRS "na"
#define CR_NUMAUTHDATA "nd"
#define CR_TICKET "t"
#define CR_TICKET2 "t2"
#define CR_AUTHTIME  "ta"
#define CR_STARTTIME  "ts"
#define CR_ENDTIME  "te"
#define CR_RENEWTILL "tr"

/*
 * take a single krb5 cred an externalize it to a buffer
 */

static int
cred_to_attr_encoding(WEBAUTH_KRB5_CTXTP *c, 
                      krb5_creds *creds, 
                      unsigned char **output, 
                      int *length,
                      time_t *expiration)
{
    WEBAUTH_ATTR_LIST *list;
    int s, length_max;

    assert(c != NULL);
    assert(creds != NULL);
    assert(output != NULL);
    assert(length != NULL);
    assert(expiration != NULL);

    list = webauth_attr_list_new(128);

    /* clent principal */
    if (creds->client) {
        char *princ;
        c->code = krb5_unparse_name(c->ctx, creds->client, &princ);
        if (c->code != 0) {
            s = WA_ERR_KRB5;
            goto cleanup;
        }
        
        s = webauth_attr_list_add_str(list, CR_CLIENT, princ, 0);
        free(princ);
        if (s != WA_ERR_NONE) 
            goto cleanup;
    }

    /* server principal */
    if (creds->server) {
        char *princ;
        c->code = krb5_unparse_name(c->ctx, creds->server, &princ);
        if (c->code != 0) {
            s = WA_ERR_KRB5;
            goto cleanup;
        }
        s = webauth_attr_list_add_str(list, CR_SERVER, princ, 0);
        free(princ);
        if (s != WA_ERR_NONE) 
            goto cleanup;
    }
    /* keyblock */
    s = webauth_attr_list_add_int32(list, CR_KEYBLOCK_ENCTYPE, 
                                    creds->keyblock.enctype);
    if (s != WA_ERR_NONE)
        goto cleanup;

    s = webauth_attr_list_add(list, CR_KEYBLOCK_CONTENTS,
                              creds->keyblock.contents,
                              creds->keyblock.length);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* times */
    s = webauth_attr_list_add_int32(list, CR_AUTHTIME, creds->times.authtime);
    if (s == WA_ERR_NONE) 
        s = webauth_attr_list_add_int32(list, CR_STARTTIME, 
                                        creds->times.starttime);
    if ( s== WA_ERR_NONE) 
        s = webauth_attr_list_add_int32(list, CR_ENDTIME,
                                        creds->times.endtime);
    if (s == WA_ERR_NONE) 
        s = webauth_attr_list_add_int32(list, CR_RENEWTILL,
                                        creds->times.renew_till);
    if (s != WA_ERR_NONE)
        goto cleanup;

    *expiration = creds->times.endtime;

    /* is_skey */
    s = webauth_attr_list_add_int32(list, CR_ISSKEY, creds->is_skey);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* ticket_flags */
    s = webauth_attr_list_add_int32(list, CR_TICKETFLAGS, creds->ticket_flags);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* addresses */
    /* FIXME: We might never want to send these? */
    /* they might not even exist if we got forwardable/proxiable tickets */
    if (creds->addresses) {
        int num = 0, i;
        char name[32];
        krb5_address **temp = creds->addresses;
        while (*temp++)
            num++;
        s = webauth_attr_list_add_int32(list, CR_NUMADDRS, num);
        if (s != WA_ERR_NONE)
            goto cleanup;
        for (i=0; i < num; i++) {
            sprintf(name, CR_ADDRTYPE, i);
            s = webauth_attr_list_add_int32(list, name,
                                            creds->addresses[i]->addrtype);
            if (s != WA_ERR_NONE)
                goto cleanup;
            sprintf(name, CR_ADDRCONT, i);
            s = webauth_attr_list_add(list, name,
                                      creds->addresses[i]->contents,
                                      creds->addresses[i]->length);
            if (s != WA_ERR_NONE)
                goto cleanup;
        }
        
    }

    /* ticket */
    if (creds->ticket.length) {
        s = webauth_attr_list_add(list, CR_TICKET,
                                  creds->ticket.data, creds->ticket.length);
        if (s != WA_ERR_NONE)
            goto cleanup;
    }

    /* second_ticket */
    if (creds->second_ticket.length) {
        s = webauth_attr_list_add(list, CR_TICKET2,
                                  creds->second_ticket.data,
                                  creds->second_ticket.length);
    }

    if (s != WA_ERR_NONE)
        goto cleanup;

    /* authdata */
    if (creds->authdata) {
        int num = 0, i;
        char name[32];
        krb5_authdata **temp = creds->authdata;
        while (*temp++)
            num++;
        s = webauth_attr_list_add_int32(list, CR_NUMAUTHDATA, num);
        if (s != WA_ERR_NONE)
            goto cleanup;
        for (i=0; i < num; i++) {
            sprintf(name, CR_AUTHDATATYPE, i);
            s = webauth_attr_list_add_int32(list, name,
                                            creds->authdata[i]->ad_type);
            if (s != WA_ERR_NONE)
                goto cleanup;
            sprintf(name, CR_AUTHDATACONT, i);
            s = webauth_attr_list_add(list, name,
                                      creds->authdata[i]->contents,
                                      creds->authdata[i]->length);
            if (s != WA_ERR_NONE)
                goto cleanup;
        }
    }


    length_max =  webauth_attrs_encoded_length(list);

    *output = malloc(length_max);
    
    if (*output == NULL) {
        s = WA_ERR_NO_MEM;
        goto cleanup;
    }

    s = webauth_attrs_encode(list, *output, length, length_max);
    if (s != WA_ERR_NONE) {
        free (*output);
        *output = NULL;
    }
 cleanup:
    webauth_attr_list_free(list);
    return s;
}


/*
 * take an externalized cred and turn it back into a cred
 */

static int
cred_from_attr_encoding(WEBAUTH_KRB5_CTXTP *c, 
                        unsigned char *input,
                        int input_length,
                        krb5_creds *creds)

{
    WEBAUTH_ATTR_LIST *list;
    int s, f;

    assert(c != NULL);
    assert(creds != NULL);
    assert(input != NULL);

    memset(creds, 0, sizeof(krb5_creds));

    s = webauth_attrs_decode(input, input_length, &list);

    if (s != WA_ERR_NONE)
        return s;

    /* clent principal */
    f = webauth_attr_list_find(list, CR_CLIENT);
    if (f != WA_ERR_NOT_FOUND) {
        c->code = krb5_parse_name(c->ctx,
                                  (char *)list->attrs[f].value,
                                  &creds->client);
        if (c->code != 0) {
            s = WA_ERR_KRB5;
            goto cleanup;
        }
    }

    /* server principal */
    f = webauth_attr_list_find(list, CR_SERVER);
    if (f != WA_ERR_NOT_FOUND) {
        c->code = krb5_parse_name(c->ctx,
                                  (char *)list->attrs[f].value,
                                  &creds->server);
        if (c->code != 0) {
            s = WA_ERR_KRB5;
            goto cleanup;
        }
    }

    /* keyblock */
    creds->keyblock.magic = KV5M_KEYBLOCK;
    s = webauth_attr_list_get_int32(list, CR_KEYBLOCK_ENCTYPE, 
                                    &creds->keyblock.enctype);
    if (s != WA_ERR_NONE)
        goto cleanup;

    f = webauth_attr_list_find(list, CR_KEYBLOCK_CONTENTS);
    if (f == WA_ERR_NOT_FOUND)
        goto cleanup;

    creds->keyblock.contents = malloc(list->attrs[f].length);
    if (creds->keyblock.contents == NULL) {
        s = WA_ERR_NO_MEM;
        goto cleanup;
    }
    creds->keyblock.length = list->attrs[f].length;
    memcpy(creds->keyblock.contents, list->attrs[f].value, 
           creds->keyblock.length);

    /* times */
    s = webauth_attr_list_get_int32(list, CR_AUTHTIME, &creds->times.authtime);
    if (s != WA_ERR_NONE)
        goto cleanup;
    s = webauth_attr_list_get_int32(list, CR_STARTTIME,
                                    &creds->times.starttime);
    if (s != WA_ERR_NONE)
        goto cleanup;
    s = webauth_attr_list_get_int32(list, CR_ENDTIME, &creds->times.endtime);
    if (s != WA_ERR_NONE)
        goto cleanup;
    s = webauth_attr_list_get_int32(list, CR_RENEWTILL,
                                    &creds->times.renew_till);
    if (s != WA_ERR_NONE)
        goto cleanup;
    /* is_skey */
    s = webauth_attr_list_get_int32(list, CR_ISSKEY, &creds->is_skey);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* ticket_flags */
    s = webauth_attr_list_get_int32(list,
                                    CR_TICKETFLAGS, &creds->ticket_flags);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* addresses */
    /* FIXME: We might never want to add these? */
    /* they might not even exist if we got forwardable/proxiable tickets */
    f = webauth_attr_list_find(list, CR_NUMADDRS);
    if (f != WA_ERR_NOT_FOUND) {
        int num = 0, i;
        char name[32];
        
        s = webauth_attr_list_get_int32(list, CR_NUMADDRS, &num);
        if (s != WA_ERR_NONE)
            goto cleanup;

        /* don't forget to add 1 to num for the null address at the
           end of the list */
        creds->addresses = 
            (krb5_address **)calloc(num+1, sizeof(krb5_address *));
        if (creds->addresses == NULL) {
            s = WA_ERR_NO_MEM;
            goto cleanup;
        }

        for (i=0; i < num; i++) {
            creds->addresses[i] = 
                (krb5_address *) malloc(sizeof(krb5_address));
            if (creds->addresses[i] == NULL) {
                goto cleanup;
            }

            creds->addresses[i]->magic = KV5M_ADDRESS;
            sprintf(name, CR_ADDRTYPE, i);
            s = webauth_attr_list_get_int32(list, name,
                                            &creds->addresses[i]->addrtype);
            if (s != WA_ERR_NONE)
                goto cleanup;
            sprintf(name, CR_ADDRCONT, i);
            f = webauth_attr_list_find(list, name);
            if (i == WA_ERR_NOT_FOUND)
                goto cleanup;

            creds->addresses[i]->contents = malloc(list->attrs[f].length);
            if (creds->addresses[i]->contents == NULL) {
                s = WA_ERR_NO_MEM;
                goto cleanup;
            }
            creds->addresses[i]->length = list->attrs[f].length;
            memcpy(creds->addresses[i]->contents, list->attrs[f].value,
                   creds->addresses[i]->length);

        }
    }

    /* ticket */
    f = webauth_attr_list_find(list, CR_TICKET);
    if (f != WA_ERR_NOT_FOUND) {
        creds->ticket.magic = KV5M_DATA;
        creds->ticket.data = malloc(list->attrs[f].length);
        if (creds->ticket.data == NULL) {
            s = WA_ERR_NO_MEM;
            goto cleanup;
        }
        creds->ticket.length = list->attrs[f].length;
        memcpy(creds->ticket.data, list->attrs[f].value, creds->ticket.length);
    }

    /* second_ticket */
    f = webauth_attr_list_find(list, CR_TICKET2);
    if (f != WA_ERR_NOT_FOUND) {
        creds->ticket.magic = KV5M_DATA;
        creds->second_ticket.data = malloc(list->attrs[f].length);
        if (creds->second_ticket.data == NULL) {
            s = WA_ERR_NO_MEM;
            goto cleanup;
        }
        creds->second_ticket.length = list->attrs[f].length;
        memcpy(creds->second_ticket.data,
               list->attrs[f].value, creds->second_ticket.length);
    }

    /* authdata */
    f = webauth_attr_list_find(list, CR_NUMAUTHDATA);
    if (f != WA_ERR_NOT_FOUND) {
        int num = 0, i;
        char name[32];
        
        s = webauth_attr_list_get_int32(list, CR_NUMAUTHDATA, &num);
        if (s != WA_ERR_NONE)
            goto cleanup;

        /* don't forget to add 1 to num for the null address at the
           end of the list */
        creds->authdata =
            (krb5_authdata **)calloc(num+1, sizeof(krb5_authdata *));
        if (creds->authdata == NULL) {
            s = WA_ERR_NO_MEM;
            goto cleanup;
        }

        for (i=0; i < num; i++) {
            creds->authdata[i] = 
                (krb5_authdata *) malloc(sizeof(krb5_authdata));
            if (creds->authdata[i] == NULL) {
                goto cleanup;
            }

            creds->authdata[i]->magic = KV5M_AUTHDATA;
            sprintf(name, CR_AUTHDATATYPE, i);
            s = webauth_attr_list_get_int32(list, name,
                                            &creds->authdata[i]->ad_type);
            if (s != WA_ERR_NONE)
                goto cleanup;
            sprintf(name, CR_AUTHDATACONT, i);
            f = webauth_attr_list_find(list, name);
            if (i == WA_ERR_NOT_FOUND)
                goto cleanup;

            creds->authdata[i]->contents = malloc(list->attrs[f].length);
            if (creds->authdata[i]->contents == NULL) {
                s = WA_ERR_NO_MEM;
                goto cleanup;
            }
            creds->authdata[i]->length = list->attrs[f].length;
            memcpy(creds->authdata[i]->contents, list->attrs[f].value,
                   creds->authdata[i]->length);
        }
    }

    s = WA_ERR_NONE;

 cleanup:
    webauth_attr_list_free(list);
    if  (s != WA_ERR_NONE)
        krb5_free_cred_contents(c->ctx, creds);
    return s;
}

static int
verify_tgt(WEBAUTH_KRB5_CTXTP *c, const char *keytab_path, const char *service)
{
    char *hname = get_hostname();
    krb5_principal server;
    krb5_keytab keytab;
    krb5_auth_context auth;
    krb5_data outbuf;

    assert(c != NULL);
    assert(keytab_path != NULL);
    assert(service != NULL);

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

WEBAUTH_KRB5_CTXT *
webauth_krb5_new()
{
    WEBAUTH_KRB5_CTXTP *c;

    c = malloc(sizeof(WEBAUTH_KRB5_CTXTP));
    if (c != NULL) {
        c->cc = NULL;
        c->princ = NULL;
        c->code = krb5_init_context(&c->ctx);
        if (c->code != 0) {
            free(c);
            c = NULL;
        }
    }

    return (WEBAUTH_KRB5_CTXT*) c;
}

int
webauth_krb5_init_via_password(WEBAUTH_KRB5_CTXT *context,
                               const char *username,
                               const char *password,
                               const char *service,
                               const char *keytab,
                               const char *cache_name)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP*)context;
    char ccname[128];
    char *tpassword;
    krb5_creds creds;
    krb5_get_init_creds_opt opts;

    assert(c != NULL);
    assert(username != NULL);
    assert(password != NULL);
    assert(service != NULL);
    assert(keytab != NULL);

    c->code = krb5_parse_name(c->ctx, username, &c->princ);

    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

    if (cache_name == NULL) {
        sprintf(ccname, "MEMORY:%p", c);
        cache_name = ccname;
    }

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
    /* FIXME: we'll need to pull some options from config
       once config is in */
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
        /*printf("code = %d\n", c->code);*/
        switch (c->code) {
            case KRB5KRB_AP_ERR_BAD_INTEGRITY:
            case KRB5KDC_ERR_PREAUTH_FAILED:
            case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
                return WA_ERR_LOGIN_FAILED;
            default:
                /* FIXME: log once logging is in */
                return WA_ERR_KRB5;
        }

    }

#if 0
    /* FIXME: remove, just testing */
    {
        unsigned char *buff;
        int l,s;
        s = cred_to_attr_encoding(c, &creds, &buff, &l);

        if (s == WA_ERR_NONE) {
            printf("encoded!\n");
            krb5_free_cred_contents(c->ctx, &creds);
            memset(&creds, 0, sizeof(creds));
            printf("nuked!\n");
            s = cred_from_attr_encoding(c, buff, l, &creds);
            if (s != WA_ERR_NONE) {
                printf("BUMMER!\n");
                assert(0);
            } else {
                printf("back from the dead!\n");
            }
            free(buff);
        }
    }
#endif

    /* add the creds to the cache */
    c->code = krb5_cc_store_cred(c->ctx, c->cc, &creds);
    krb5_free_cred_contents(c->ctx, &creds);
    if (c->code != 0) {
        return WA_ERR_KRB5;
    } else {
        /* lets see if the credentials are valid */
        return verify_tgt(c, keytab, service);
    }
}


int
webauth_krb5_free(WEBAUTH_KRB5_CTXT *context, int destroy_cache)
{    
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP*)context;
    assert(c != NULL);

    if (c->cc) {
        if (destroy_cache) {
            krb5_cc_destroy(c->ctx, c->cc);
        } else {
            krb5_cc_close(c->ctx, c->cc);
        }
    }
    if (c->princ) {
        krb5_free_principal(c->ctx, c->princ);
    }
    krb5_free_context(c->ctx);
    free(context);
    return WA_ERR_NONE;
}

int
webauth_krb5_mk_req(WEBAUTH_KRB5_CTXT *context,
                    const char *hostname,
                    const char *service,
                    unsigned char **output,
                    int *length)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP*)context;
    krb5_auth_context auth;
    krb5_data outbuf;
    int s;

    assert(c != NULL);
    assert(hostname != NULL);
    assert(service != NULL);
    assert(output != NULL);
    assert(length != NULL);

    auth = NULL;
    c->code = krb5_mk_req(c->ctx, &auth, 0, (char*)service, (char*)hostname, 
                          NULL, c->cc, &outbuf);

    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

    if (auth != NULL) {
        krb5_auth_con_free(c->ctx, auth);
    }

    *output = malloc(outbuf.length);
    if (*output == NULL) {
        s = WA_ERR_NO_MEM;
    } else {
        *length = outbuf.length;
        memcpy(*output, outbuf.data, outbuf.length);
        s = WA_ERR_NONE;
    }
    krb5_free_data_contents(c->ctx, &outbuf);    
    return s;
}

int
webauth_krb5_rd_req(WEBAUTH_KRB5_CTXT *context,
                    const unsigned char *req,
                    int length,
                    const char *service,
                    const char *keytab_path,
                    char **client_principal)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP*)context;
    char *hname = get_hostname();
    krb5_principal server;
    krb5_keytab keytab;
    krb5_auth_context auth;
    krb5_data buf;

    assert(c != NULL);
    assert(keytab_path != NULL);
    assert(req != NULL);
    assert(service != NULL);
    assert(client_principal);

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

    buf.data = (char*) req;
    buf.length = length;
    c->code = krb5_rd_req(c->ctx, &auth, &buf, server, keytab, NULL, NULL);
    if (c->code == 0) {
        if (auth != NULL) {
            krb5_authenticator *ka;
            c->code = krb5_auth_con_getauthenticator(c->ctx, auth, &ka);
            if (c->code == 0) {
                c->code = krb5_unparse_name(c->ctx, ka->client, 
                                            client_principal);
                krb5_free_authenticator(c->ctx, ka);
            } else {
                *client_principal = NULL;
            }
            krb5_auth_con_free(c->ctx, auth);
        }
    }

    krb5_kt_close(c->ctx, keytab);
    krb5_free_principal(c->ctx, server);

    return (c->code == 0) ? WA_ERR_NONE : WA_ERR_KRB5;
}

int
webauth_krb5_init_from_keytab(WEBAUTH_KRB5_CTXT *context, char *path)
{
    return WA_ERR_NONE;
}

int
webauth_krb5_init_via_tgt(WEBAUTH_KRB5_CTXT *context,
                          unsigned char *tgt,
                          int tgt_len,
                          const char *cache_name)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP*)context;
    krb5_creds creds;
    char ccname[128];
    int s;

    assert(c != NULL);
    assert(tgt != NULL);

    s = cred_from_attr_encoding(c, tgt, tgt_len, &creds);

    if (s!= WA_ERR_NONE) 
        return WA_ERR_KRB5;


    if (cache_name == NULL) {
        sprintf(ccname, "MEMORY:%p", c);
        cache_name = ccname;
    }
    c->code = krb5_cc_resolve(c->ctx, ccname, &c->cc);

    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

    c->code = krb5_copy_principal(c->ctx, creds.client, &c->princ);
    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

    c->code = krb5_cc_initialize(c->ctx, c->cc, c->princ);

    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

    /* add the creds to the cache */
    c->code = krb5_cc_store_cred(c->ctx, c->cc, &creds);
    krb5_free_cred_contents(c->ctx, &creds);
    if (c->code != 0) {
        return WA_ERR_KRB5;
    } else {
        return WA_ERR_NONE;
    }
}

int
webauth_krb5_export_tgt(WEBAUTH_KRB5_CTXT *context,
                        unsigned char **tgt,
                        int *tgt_len,
                        time_t *expiration)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP*)context;
    krb5_principal tgtprinc, client;
    krb5_data *client_realm;
    krb5_creds creds, tgtq;
    int s;

    assert(c != NULL);
    assert(tgt != NULL);
    assert(tgt_len != NULL);
    assert(expiration != NULL);

    /* first we need to find tgt in cache */
    c->code = krb5_cc_get_principal(c->ctx, c->cc, &client);
    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

    client_realm = krb5_princ_realm(c->ctx, client);
    c->code = krb5_build_principal_ext(c->ctx,
                                       &tgtprinc,
                                       client_realm->length,
                                       client_realm->data,
                                       KRB5_TGS_NAME_SIZE,
                                       KRB5_TGS_NAME,
                                       client_realm->length,
                                       client_realm->data,
                                       0);

    if (c->code != 0) {
        krb5_free_principal(c->ctx, client);        
        return WA_ERR_KRB5;
    }

    memset(&tgtq, 0, sizeof(tgtq));
    memset(&creds, 0, sizeof(creds));

    tgtq.server = tgtprinc;
    tgtq.client = client;

    c->code = krb5_cc_retrieve_cred(c->ctx, 
                                    c->cc,
                                    KRB5_TC_MATCH_SRV_NAMEONLY,
                                    &tgtq,
                                    &creds);

    if (c->code == 0) {
        s = cred_to_attr_encoding(c, &creds, tgt, tgt_len, expiration);
        krb5_free_cred_contents(c->ctx, &creds);
    } else {
        s = WA_ERR_KRB5;
    }

    krb5_free_principal(c->ctx, client);
    krb5_free_principal(c->ctx, tgtprinc);

    return s;
}

int
webauth_krb5_import_ticket(WEBAUTH_KRB5_CTXT *context,
                           unsigned char *ticket,
                           int ticket_len)
{
    return WA_ERR_NONE;
}

int
webauth_krb5_export_ticket(WEBAUTH_KRB5_CTXT *context,
                           char *service,
                           unsigned char **ticket,
                           int *ticket_length)
{
    return WA_ERR_NONE;
}
