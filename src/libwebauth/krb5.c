
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

#if 0

/* we don't need this now, though we did at one point. Keeping
   it if'd out for now in case... */

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
#endif

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

    s = webauth_attr_list_get_void(list, CR_KEYBLOCK_CONTENTS,
                                   (void**)&creds->keyblock.contents,
                                   &creds->keyblock.length);
    if (s != WA_ERR_NONE)
        goto cleanup;

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

            s = webauth_attr_list_get_void(list, name,
                                      (void**)&creds->addresses[i]->contents,
                                      &creds->addresses[i]->length);
            if (s != WA_ERR_NONE)
                goto cleanup;
        }
    }

    /* ticket */
    f = webauth_attr_list_find(list, CR_TICKET);
    if (f != WA_ERR_NOT_FOUND) {
        creds->ticket.magic = KV5M_DATA;

        s = webauth_attr_list_get_void(list, CR_TICKET,
                                       (void**)&creds->ticket.data,
                                       &creds->ticket.length);
        if (s != WA_ERR_NONE)
            goto cleanup;
    }

    /* second_ticket */
    f = webauth_attr_list_find(list, CR_TICKET2);
    if (f != WA_ERR_NOT_FOUND) {
        creds->ticket.magic = KV5M_DATA;

        s = webauth_attr_list_get_void(list, CR_TICKET2,
                                       (void**)&creds->second_ticket.data,
                                       &creds->second_ticket.length);
        if (s != WA_ERR_NONE)
            goto cleanup;
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

            s = webauth_attr_list_get_void(list, name,
                                        (void**)&creds->authdata[i]->contents,
                                        &creds->authdata[i]->length);
            if (s != WA_ERR_NONE)
                goto cleanup;
        }
    }

    s = WA_ERR_NONE;

 cleanup:
    webauth_attr_list_free(list);
    if  (s != WA_ERR_NONE)
        krb5_free_cred_contents(c->ctx, creds);
    return s;
}

/* 
 * get the principal from a keytab. this assumes only one principal
 * per keytab, which is normally the case.
 */
static int
get_principal_from_keytab(WEBAUTH_KRB5_CTXTP *c,
                          const char *keytab_path,
                          krb5_principal *princ,
                          krb5_keytab *id_out)
{
    krb5_keytab id;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_error_code tcode;

    assert(c != NULL);
    assert(keytab_path != NULL);
    assert(princ != NULL);
    assert(id_out);

    c->code = krb5_kt_resolve(c->ctx, keytab_path, &id);
    if (c->code != 0)
        return WA_ERR_KRB5;

    c->code = krb5_kt_start_seq_get(c->ctx, id, &cursor);
    if (c->code != 0) {
        /* FIXME: when logging is in, log if error if tcode != 0*/
        tcode = krb5_kt_close(c->ctx, id);
        return WA_ERR_KRB5;
    }

    c->code = krb5_kt_next_entry(c->ctx, id, &entry, &cursor);
    if (c->code == 0) {
        c->code = krb5_copy_principal(c->ctx, entry.principal, princ);
        /* use tcode fromt this point so we don't lose value of c->code */
        /* FIXME: when logging is in, log if error if tcode != 0 */
        tcode = krb5_kt_free_entry(c->ctx, &entry);
    }
    /* FIXME: when logging is in, log if error if tcode != 0 */
    tcode = krb5_kt_end_seq_get(c->ctx, id, &cursor);

    if (c->code == 0) {
        *id_out = id;
        return WA_ERR_NONE;
    } else {
        *id_out = NULL;
        tcode = krb5_kt_close(c->ctx, id);
        return WA_ERR_KRB5;
    }
}


/* like krb5_mk_req, but takes a principal instead of a service/host */
static krb5_error_code
mk_req_with_principal(krb5_context context, 
                      krb5_auth_context *auth_context, 
                      krb5_flags ap_req_options, 
                      krb5_principal server, 
                      krb5_data *in_data,
                      krb5_ccache ccache,
                      krb5_data *outbuf)
{
    krb5_error_code 	  retval;
    krb5_creds 		* credsp;
    krb5_creds 		  creds;

    /* obtain ticket & session key */
    memset((char *)&creds, 0, sizeof(creds));
    if ((retval = krb5_copy_principal(context, server, &creds.server)))
        return retval;

    if ((retval = krb5_cc_get_principal(context, ccache, &creds.client)))
	goto cleanup_creds;

    if ((retval = krb5_get_credentials(context, 0,
				       ccache, &creds, &credsp)))
	goto cleanup_creds;

    retval = krb5_mk_req_extended(context, auth_context, ap_req_options, 
				  in_data, credsp, outbuf);

    krb5_free_creds(context, credsp);

 cleanup_creds:
    krb5_free_cred_contents(context, &creds);
    return retval;
}

static int
verify_tgt(WEBAUTH_KRB5_CTXTP *c, const char *keytab_path)
{
    krb5_principal server;
    krb5_keytab keytab;
    krb5_auth_context auth;
    krb5_data outbuf;
    int s;

    assert(c != NULL);
    assert(keytab_path != NULL);

    s = get_principal_from_keytab(c, keytab_path, &server, &keytab);
    if (s != WA_ERR_NONE)
        return s;

    auth = NULL;
    c->code = mk_req_with_principal(c->ctx, &auth, 0, server, 
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
    assert(keytab != NULL);

    c->code = krb5_parse_name(c->ctx, username, &c->princ);

    if (c->code != 0) {
        return WA_ERR_KRB5;
    }

    if (cache_name == NULL) {
        sprintf(ccname, "MEMORY:%p", c);
        cache_name = ccname;
    }

    c->code = krb5_cc_resolve(c->ctx, cache_name, &c->cc);
    if (c->code != 0) 
        return WA_ERR_KRB5;

    c->code = krb5_cc_initialize(c->ctx, c->cc, c->princ);
    if (c->code != 0) 
        return WA_ERR_KRB5;

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

    memset(tpassword, 0, strlen(tpassword));
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

    /* add the creds to the cache */
    c->code = krb5_cc_store_cred(c->ctx, c->cc, &creds);
    krb5_free_cred_contents(c->ctx, &creds);
    if (c->code != 0) {
        return WA_ERR_KRB5;
    } else {
        /* lets see if the credentials are valid */
        return verify_tgt(c, keytab);
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
                    const char *server_principal,
                    unsigned char **output,
                    int *length)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP*)context;
    krb5_auth_context auth;
    krb5_data outbuf;
    krb5_principal princ;
    int s;

    assert(c != NULL);
    assert(server_principal != NULL);
    assert(output != NULL);
    assert(length != NULL);

    c->code = krb5_parse_name(c->ctx, server_principal, &princ);
    if (c->code != 0)
        return WA_ERR_KRB5;

    auth = NULL;
    c->code = mk_req_with_principal(c->ctx, &auth, 0, princ,
                                    NULL, c->cc, &outbuf);
    krb5_free_principal(c->ctx, princ);

    if (c->code != 0)
        return WA_ERR_KRB5;

    if (auth != NULL)
        krb5_auth_con_free(c->ctx, auth);

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
                    const char *keytab_path,
                    char **client_principal)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP*)context;
    krb5_principal server;
    krb5_keytab keytab;
    krb5_auth_context auth;
    krb5_data buf;
    int s;

    assert(c != NULL);
    assert(keytab_path != NULL);
    assert(req != NULL);
    assert(client_principal);

    s = get_principal_from_keytab(c, keytab_path, &server, &keytab);
    if (s != WA_ERR_NONE)
        return s;

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
webauth_krb5_init_via_keytab(WEBAUTH_KRB5_CTXT *context, 
                             const char *keytab_path,
                             const char *cache_name)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP*)context;
    char ccname[128];
    krb5_creds creds;
    krb5_get_init_creds_opt opts;
    krb5_keytab keytab;
    krb5_error_code tcode;
    int s;

    assert(c != NULL);
    assert(keytab_path != NULL);

    if (c->princ != NULL)
        krb5_free_principal(c->ctx, c->princ);

    s = get_principal_from_keytab(c, keytab_path, &c->princ, &keytab);
    if (s != WA_ERR_NONE) 
        return WA_ERR_KRB5;

    if (cache_name == NULL) {
        sprintf(ccname, "MEMORY:%p", c);
        cache_name = ccname;
    }

    c->code = krb5_cc_resolve(c->ctx, cache_name, &c->cc);
    if (c->code != 0) {
        tcode = krb5_kt_close(c->ctx, keytab);
        return WA_ERR_KRB5;
    }

    c->code = krb5_cc_initialize(c->ctx, c->cc, c->princ);
    if (c->code != 0) {
        tcode = krb5_kt_close(c->ctx, keytab);
        return WA_ERR_KRB5;
    }

    krb5_get_init_creds_opt_init(&opts);

    c->code = krb5_get_init_creds_keytab(c->ctx,
                                         &creds,
                                         c->princ,
                                         keytab,
                                         NULL, /* start_time */
                                         NULL, /* in_tkt_service */
                                         &opts);

    /* FIXME: when logging is in, log if error if tcode != 0*/
    tcode = krb5_kt_close(c->ctx, keytab);


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
        return s;


    if (cache_name == NULL) {
        sprintf(ccname, "MEMORY:%p", c);
        cache_name = ccname;
    }
    c->code = krb5_cc_resolve(c->ctx, cache_name, &c->cc);

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
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP*)context;
    krb5_creds creds;
    int s;

    assert(c != NULL);
    assert(ticket!= NULL);

    s = cred_from_attr_encoding(c, ticket, ticket_len, &creds);
    if (s!= WA_ERR_NONE) 
        return s;

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
webauth_krb5_export_ticket(WEBAUTH_KRB5_CTXT *context,
                           char *server_principal,
                           unsigned char **ticket,
                           int *ticket_len,
                           time_t *expiration)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP*)context;
    krb5_creds *credsp, creds;
    int s;

    s = WA_ERR_KRB5;
    memset((char *)&creds, 0, sizeof(creds));

    c->code = krb5_parse_name(c->ctx, server_principal, &creds.server);
    if (c->code != 0)
        goto cleanup_creds;

    c->code = krb5_cc_get_principal(c->ctx, c->cc, &creds.client);
    if (c->code != 0)
	goto cleanup_creds;

    c->code = krb5_get_credentials(c->ctx, 0, c->cc, &creds, &credsp);
    if (c->code != 0)
	goto cleanup_creds;

    s = cred_to_attr_encoding(c, credsp, ticket, ticket_len, expiration);
    krb5_free_creds(c->ctx, credsp);

 cleanup_creds:
    krb5_free_cred_contents(c->ctx, &creds);
    return s;
}

int
webauth_krb5_service_principal(WEBAUTH_KRB5_CTXT *context,
                               const char *service,
                               const char *hostname,
                               char **server_principal)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP*)context;
    krb5_principal princ;

    c->code = krb5_sname_to_principal(c->ctx,
                                      hostname,
                                      service,
                                      KRB5_NT_SRV_HST,
                                      &princ);
    if (c->code != 0)
        return WA_ERR_KRB5;

    c->code = krb5_unparse_name(c->ctx, princ, server_principal);
    krb5_free_principal(c->ctx, princ);

    return c->code == 0 ? WA_ERR_NONE : WA_ERR_KRB5;
}
