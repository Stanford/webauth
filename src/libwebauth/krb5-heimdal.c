/*  $Id$
**
**  Heimdal Kerberos interface for WebAuth.
**
**  This file is *included* (via the preprocessor) in krb5.c for systems that
**  use Heimdal Kerberos.  If you make any changes here, you probably also
**  need to make a corresponding change to krb5-mit.c for systems with MIT
**  Kerberos.
*/

/*
 * take a single krb5 cred an externalize it to a buffer
 */

static int
cred_to_attr_encoding(WEBAUTH_KRB5_CTXTP *c, 
                      krb5_creds *creds, 
                      char **output, 
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
        
        s = webauth_attr_list_add_str(list, CR_CLIENT, princ, 0, 
                                      WA_F_COPY_VALUE);
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
        s = webauth_attr_list_add_str(list, CR_SERVER, princ, 0, 
                                      WA_F_COPY_VALUE);
        free(princ);
        if (s != WA_ERR_NONE) 
            goto cleanup;
    }
    /* keyblock */
    s = webauth_attr_list_add_int32(list, CR_KEYBLOCK_ENCTYPE, 
                                    creds->session.keytype, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;

    s = webauth_attr_list_add(list, CR_KEYBLOCK_CONTENTS,
                              creds->session.keyvalue.data,
                              creds->session.keyvalue.length, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* times */
    s = webauth_attr_list_add_int32(list, 
                                    CR_AUTHTIME, 
                                    creds->times.authtime, WA_F_NONE);
    if (s == WA_ERR_NONE) 
        s = webauth_attr_list_add_int32(list, CR_STARTTIME, 
                                        creds->times.starttime, WA_F_NONE);
    if ( s== WA_ERR_NONE) 
        s = webauth_attr_list_add_int32(list, CR_ENDTIME,
                                        creds->times.endtime, WA_F_NONE);
    if (s == WA_ERR_NONE) 
        s = webauth_attr_list_add_int32(list, CR_RENEWTILL,
                                        creds->times.renew_till, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;

    *expiration = creds->times.endtime;

    /* is_skey */
    s = webauth_attr_list_add_int32(list, CR_ISSKEY, 0, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* ticket_flags */
    s = webauth_attr_list_add_int32(list, CR_TICKETFLAGS,
                                    creds->flags.i, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* addresses */
    /* FIXME: We might never want to send these? */
    if (creds->addresses.len > 0) {
        int i;
        char name[32];
        krb5_address *temp;

        s = webauth_attr_list_add_int32(list, CR_NUMADDRS,
                                        creds->addresses.len, WA_F_NONE);
        if (s != WA_ERR_NONE)
            goto cleanup;
        for (i = 0; i < creds->addresses.len; i++) {
            temp = creds->addresses.val + i;
            sprintf(name, CR_ADDRTYPE, i);
            s = webauth_attr_list_add_int32(list, name,
                                            temp->addr_type,
                                            WA_F_COPY_NAME);
            if (s != WA_ERR_NONE)
                goto cleanup;
            sprintf(name, CR_ADDRCONT, i);
            s = webauth_attr_list_add(list, name,
                                      temp->address.data,
                                      temp->address.length,
                                      WA_F_COPY_NAME);
            if (s != WA_ERR_NONE)
                goto cleanup;
        }
    }

    /* ticket */
    if (creds->ticket.length) {
        s = webauth_attr_list_add(list, CR_TICKET,
                                  creds->ticket.data, 
                                  creds->ticket.length, WA_F_NONE);
        if (s != WA_ERR_NONE)
            goto cleanup;
    }

    /* second_ticket */
    if (creds->second_ticket.length) {
        s = webauth_attr_list_add(list, CR_TICKET2,
                                  creds->second_ticket.data,
                                  creds->second_ticket.length, WA_F_NONE);
    }

    if (s != WA_ERR_NONE)
        goto cleanup;

    /* authdata */
    if (creds->authdata.len > 0) {
        int i;
        char name[32];

        s = webauth_attr_list_add_int32(list, CR_NUMAUTHDATA,
                                        creds->authdata.len, WA_F_NONE);
        if (s != WA_ERR_NONE)
            goto cleanup;
        for (i = 0; i < creds->authdata.len; i++) {
            sprintf(name, CR_AUTHDATATYPE, i);
            s = webauth_attr_list_add_int32(list, name,
                                            creds->authdata.val[i].ad_type,
                                            WA_F_COPY_NAME);
            if (s != WA_ERR_NONE)
                goto cleanup;
            sprintf(name, CR_AUTHDATACONT, i);
            s = webauth_attr_list_add(list, name,
                                      creds->authdata.val[i].ad_data.data,
                                      creds->authdata.val[i].ad_data.length,
                                      WA_F_COPY_NAME);
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
                        char *input,
                        int input_length,
                        krb5_creds *creds)

{
    WEBAUTH_ATTR_LIST *list;
    int s, f;
    char *buff;
    int temp_int;
    int32_t temp_int32;

    assert(c != NULL);
    assert(creds != NULL);
    assert(input != NULL);

    memset(creds, 0, sizeof(krb5_creds));

    list = NULL;
    buff = malloc(input_length);

    if (buff == NULL)
        return WA_ERR_NO_MEM;

    memcpy(buff, input, input_length);

    s = webauth_attrs_decode(buff, input_length, &list);

    if (s != WA_ERR_NONE) 
        goto cleanup;

    /* clent principal */
    webauth_attr_list_find(list, CR_CLIENT, &f);
    if (f != -1) {
        c->code = krb5_parse_name(c->ctx,
                                  list->attrs[f].value,
                                  &creds->client);
        if (c->code != 0) {
            s = WA_ERR_KRB5;
            goto cleanup;
        }
    }

    /* server principal */
    webauth_attr_list_find(list, CR_SERVER, &f);
    if (f != -1) {
        c->code = krb5_parse_name(c->ctx,
                                  list->attrs[f].value,
                                  &creds->server);
        if (c->code != 0) {
            s = WA_ERR_KRB5;
            goto cleanup;
        }
    }

    /* keyblock */
    s = webauth_attr_list_get_int32(list, CR_KEYBLOCK_ENCTYPE, 
                                    &temp_int32, WA_F_NONE);
    creds->session.keytype = temp_int32;
    if (s != WA_ERR_NONE)
        goto cleanup;

    s = webauth_attr_list_get(list, CR_KEYBLOCK_CONTENTS,
                              &creds->session.keyvalue.data, &temp_int,
                              WA_F_COPY_VALUE);
    creds->session.keyvalue.length = temp_int;
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* times */
    s = webauth_attr_list_get_int32(list, CR_AUTHTIME, 
                                    &temp_int32, WA_F_NONE);
    creds->times.authtime = temp_int32;
    if (s != WA_ERR_NONE)
        goto cleanup;

    s = webauth_attr_list_get_int32(list, CR_STARTTIME,
                                    &temp_int32, WA_F_NONE);
    creds->times.starttime = temp_int32;
    if (s != WA_ERR_NONE)
        goto cleanup;

    s = webauth_attr_list_get_int32(list, CR_ENDTIME, 
                                    &temp_int32, WA_F_NONE);
    creds->times.endtime = temp_int32;
    if (s != WA_ERR_NONE)
        goto cleanup;

    s = webauth_attr_list_get_int32(list, CR_RENEWTILL,
                                    &temp_int32, WA_F_NONE);
    creds->times.renew_till = temp_int32;
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* is_skey is not supported by Heimdal, so ignore it. */

    /* ticket_flags */
    s = webauth_attr_list_get_int32(list, CR_TICKETFLAGS, 
                                    (int32_t *) &creds->flags.i, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* addresses */
    /* FIXME: We might never want to add these? */
    /* they might not even exist if we got forwardable/proxiable tickets */
    webauth_attr_list_find(list, CR_NUMADDRS, &f);
    if (f != -1) {
        int num = 0, i;
        char name[32];
        
        s = webauth_attr_list_get_int32(list, CR_NUMADDRS, &num, WA_F_NONE);
        if (s != WA_ERR_NONE)
            goto cleanup;

        creds->addresses.len = num;
        creds->addresses.val = calloc(num, sizeof(krb5_address));
        if (creds->addresses.val == NULL) {
            s = WA_ERR_NO_MEM;
            goto cleanup;
        }

        for (i = 0; i < num; i++) {
            sprintf(name, CR_ADDRTYPE, i);
            s = webauth_attr_list_get_int32(list, name,
                                            &temp_int32, WA_F_NONE);
            if (s != WA_ERR_NONE)
                goto cleanup;
            creds->addresses.val[i].addr_type = temp_int32;

            sprintf(name, CR_ADDRCONT, i);
            s = webauth_attr_list_get(list, name,
                                      &creds->addresses.val[i].address.data,
                                      &temp_int, WA_F_COPY_VALUE);
            if (s != WA_ERR_NONE)
                goto cleanup;
            creds->addresses.val[i].address.length = temp_int;
        }
    }

    /* ticket */
    webauth_attr_list_find(list, CR_TICKET, &f);
    if (f != -1) {
        s = webauth_attr_list_get(list, CR_TICKET,
                                  &creds->ticket.data,
                                  &temp_int, WA_F_COPY_VALUE);
        if (s != WA_ERR_NONE)
            goto cleanup;
        creds->ticket.length = temp_int;
    }

    /* second_ticket */
    webauth_attr_list_find(list, CR_TICKET2, &f);
    if (f != -1) {
        s = webauth_attr_list_get(list, CR_TICKET2,
                                  &creds->second_ticket.data,
                                  &temp_int, WA_F_COPY_VALUE);
        if (s != WA_ERR_NONE)
            goto cleanup;
        creds->second_ticket.length = temp_int;
    }

    /* authdata */
    webauth_attr_list_find(list, CR_NUMAUTHDATA, &f);
    if (f != -1) {
        int num = 0, i;
        char name[32];
        
        s = webauth_attr_list_get_int32(list, CR_NUMAUTHDATA, &num, WA_F_NONE);
        if (s != WA_ERR_NONE)
            goto cleanup;

        creds->authdata.len = num;
        creds->authdata.val = calloc(num, sizeof(*creds->authdata.val));
        if (creds->authdata.val == NULL) {
            s = WA_ERR_NO_MEM;
            goto cleanup;
        }

        for (i = 0; i < num; i++) {
            sprintf(name, CR_AUTHDATATYPE, i);
            s = webauth_attr_list_get_int32(list, name,
                                            &temp_int32, WA_F_NONE);
            if (s != WA_ERR_NONE)
                goto cleanup;
            creds->authdata.val[i].ad_type = temp_int32;

            sprintf(name, CR_AUTHDATACONT, i);
            s = webauth_attr_list_get(list, name,
                                      &creds->authdata.val[i].ad_data.data,
                                      &temp_int, WA_F_COPY_VALUE);
            if (s != WA_ERR_NONE)
                goto cleanup;
            creds->authdata.val[i].ad_data.length = temp_int;
        }
    }

    s = WA_ERR_NONE;

 cleanup:
    if (buff != NULL) 
        free(buff);

    if (list != NULL) 
        webauth_attr_list_free(list);

    if  (s != WA_ERR_NONE)
        krb5_free_cred_contents(c->ctx, creds);

    return s;
}

int
webauth_krb5_mk_req_with_data(WEBAUTH_KRB5_CTXT *context,
                              const char *server_principal,
                              char **output,
                              int *length,
                              char *in_data,
                              int in_length,
                              char **out_data,
                              int *out_length)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    krb5_auth_context auth;
    krb5_data outbuf;
    krb5_principal princ;
    int s;

    assert(c != NULL);
    assert(server_principal != NULL);
    assert(output != NULL);
    assert(length != NULL);

    memset(&outbuf, 0, sizeof(krb5_data));
    *output = NULL;
    if (out_data)
        *output = NULL;

    c->code = krb5_parse_name(c->ctx, server_principal, &princ);
    if (c->code != 0)
        return WA_ERR_KRB5;

    auth = NULL;
    c->code = mk_req_with_principal(c->ctx, &auth, 0, princ,
                                    NULL, c->cc, &outbuf);
    krb5_free_principal(c->ctx, princ);

    if (c->code != 0)
        return WA_ERR_KRB5;

    *output = malloc(outbuf.length);
    if (*output == NULL) {
        s = WA_ERR_NO_MEM;
        krb5_free_data_contents(c->ctx, &outbuf);
        goto cleanup;
    } else {
        *length = outbuf.length;
        memcpy(*output, outbuf.data, outbuf.length);
        s = WA_ERR_NONE;
        krb5_free_data_contents(c->ctx, &outbuf);
    }

    if (in_data != NULL && out_data != NULL) {
        krb5_data indata, outdata;
        /*krb5_address **laddrs;*/
        krb5_address laddr;
        char lh[4] = {127, 0, 0, 1};

        laddr.addr_type = KRB5_ADDRESS_INET;
        laddr.address.length = 4;
        laddr.address.data = (void *) &lh;

        indata.data = in_data;
        indata.length = in_length;

        krb5_auth_con_setflags(c->ctx, auth, 0);
        /*krb5_os_localaddr(c->ctx, &laddrs);*/
        /*krb5_auth_con_setaddrs(c->ctx, auth, laddrs[0], NULL);*/
        /*krb5_free_addresses(c->ctx, laddrs);*/
        krb5_auth_con_setaddrs(c->ctx, auth, &laddr, NULL);

        c->code = krb5_mk_priv(c->ctx, auth, &indata, &outdata, NULL);
        if (c->code == 0) {
            s = WA_ERR_NONE;

            *out_data = malloc(outdata.length);
            if (*out_data == NULL) {
                s = WA_ERR_NO_MEM;
            } else {
                *out_length = outdata.length;
                memcpy(*out_data, outdata.data, outdata.length);
                s = WA_ERR_NONE;
            }
            krb5_free_data_contents(c->ctx, &outdata);
        } else {
            s = WA_ERR_KRB5;
        }
    }

 cleanup:

    if (s != WA_ERR_NONE) {
        if (*output != NULL)
            free(*output);
    }
        
    if (auth != NULL)
        krb5_auth_con_free(c->ctx, auth);

    return s;
}

int
webauth_krb5_rd_req_with_data(WEBAUTH_KRB5_CTXT *context,
                              const char *req,
                              int length,
                              const char *keytab_path,
                              const char *server_principal,
                              char **out_server_principal,
                              char **client_principal,
                              int local,
                              char *in_data,
                              int in_length,
                              char **out_data,
                              int *out_length)

{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    krb5_principal server;
    krb5_keytab keytab;
    krb5_auth_context auth;
    krb5_data buf;
    int s;

    assert(c != NULL);
    assert(keytab_path != NULL);
    assert(req != NULL);
    assert(client_principal);

    s = open_keytab(c, keytab_path, server_principal, &server, &keytab);
    if (s != WA_ERR_NONE)
        return s;

    auth = NULL;

    if (out_server_principal)
        *out_server_principal = NULL;

    buf.data = (char *) req;
    buf.length = length;
    c->code = krb5_rd_req(c->ctx, &auth, &buf, server, keytab, NULL, NULL);
    if (c->code == 0) {
        if (out_server_principal)
            krb5_unparse_name(c->ctx, server, out_server_principal);
        if (auth != NULL) {
            krb5_authenticator ka;

            c->code = krb5_auth_con_getauthenticator(c->ctx, auth, &ka);
            if (c->code == 0) {
                int local_ok = 0;
                krb5_principal_data kprinc;

                kprinc.name = ka->cname;
                kprinc.realm = ka->crealm;

                if (local) {
                    krb5_error_code tcode;
                    char lname[256];

                    tcode = krb5_aname_to_localname(c->ctx, &kprinc,
                                                    sizeof(lname) - 1,
                                                    lname);
                    if (tcode == 0) {
                        *client_principal = malloc(strlen(lname)+1);
                        strcpy(*client_principal, lname);
                        local_ok = 1;
                    } 
                }

                if (!local_ok)
                    c->code = krb5_unparse_name(c->ctx, &kprinc,
                                                client_principal);

                if (in_data != NULL && out_data != NULL) {
                    krb5_data inbuf, outbuf;
                    krb5_address raddr;
                    char rh[4] = {127, 0, 0, 1};

                    raddr.addr_type = KRB5_ADDRESS_INET;
                    raddr.address.length = 4;
                    raddr.address.data = (void *) &rh;

                    inbuf.data = in_data;
                    inbuf.length = in_length;
                    krb5_auth_con_setflags(c->ctx, auth, 0);
                    krb5_auth_con_setaddrs(c->ctx, auth, NULL, &raddr);
                    c->code = krb5_rd_priv(c->ctx, auth, 
                                           &inbuf, &outbuf, NULL);
                    if (c->code == 0) {
                        *out_data = malloc(outbuf.length);
                        if (*out_data == NULL) {
                            s = WA_ERR_NO_MEM;
                        } else {
                            s = WA_ERR_NONE;
                            *out_length = outbuf.length;
                            memcpy(*out_data, outbuf.data, outbuf.length);
                        }
                        krb5_free_data_contents(c->ctx, &outbuf);
                    }

                }
                krb5_free_authenticator(c->ctx, &ka);

            } else {
                *client_principal = NULL;
            }
            krb5_auth_con_free(c->ctx, auth);
        }
    }

    krb5_kt_close(c->ctx, keytab);
    krb5_free_principal(c->ctx, server);

    if (s == WA_ERR_NONE && c->code != 0)
        s = WA_ERR_KRB5;

    if (s != WA_ERR_NONE) {
        if (out_server_principal && *out_server_principal != NULL)
            free(*out_server_principal);
    }

    return s;
}

int
webauth_krb5_export_tgt(WEBAUTH_KRB5_CTXT *context,
                        char **tgt,
                        int *tgt_len,
                        time_t *expiration)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    krb5_principal tgtprinc, client;
    krb5_realm *client_realm;
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
                                       krb5_realm_length(*client_realm),
                                       krb5_realm_data(*client_realm),
                                       KRB5_TGS_NAME_SIZE,
                                       KRB5_TGS_NAME,
                                       krb5_realm_length(*client_realm),
                                       krb5_realm_data(*client_realm),
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
