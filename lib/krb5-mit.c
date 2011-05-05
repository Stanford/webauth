/*
 * MIT Kerberos interface for WebAuth.
 *
 * This file is *included* (via the preprocessor) in krb5.c for systems that
 * use MIT Kerberos.  If you make any changes here, you probably also need to
 * make a corresponding change to krb5-heimdal.c for systems with Heimdal.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Based on the original Kerberos support code by Roland Schemers
 * Copyright 2002, 2003, 2006, 2009, 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

/*
 * Take a single Kerberos v5 credential and serialize it into a buffer, using
 * the encoding required for putting it into tokens.  output will be a pointer
 * to newly allocated memory, and length will be set to the encoded length.
 * expiration will be set to the expiration time of the ticket.  Returns a
 * WA_ERR code.
 */
static int
cred_to_attr_encoding(WEBAUTH_KRB5_CTXTP *c, krb5_creds *creds,
                      char **output, size_t *length, time_t *expiration)
{
    WEBAUTH_ATTR_LIST *list;
    int s;
    size_t length_max;

    assert(c != NULL);
    assert(creds != NULL);
    assert(output != NULL);
    assert(length != NULL);
    assert(expiration != NULL);

    list = webauth_attr_list_new(128);

    /* Clent principal. */
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

    /* Server principal. */
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

    /* Keyblock. */
    s = webauth_attr_list_add_int32(list, CR_KEYBLOCK_ENCTYPE,
                                    creds->keyblock.enctype, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;
    s = webauth_attr_list_add(list, CR_KEYBLOCK_CONTENTS,
                              creds->keyblock.contents,
                              creds->keyblock.length, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* Times. */
    s = webauth_attr_list_add_int32(list, CR_AUTHTIME,
                                    creds->times.authtime, WA_F_NONE);
    if (s == WA_ERR_NONE)
        s = webauth_attr_list_add_int32(list, CR_STARTTIME,
                                        creds->times.starttime, WA_F_NONE);
    if (s == WA_ERR_NONE)
        s = webauth_attr_list_add_int32(list, CR_ENDTIME,
                                        creds->times.endtime, WA_F_NONE);
    if (s == WA_ERR_NONE)
        s = webauth_attr_list_add_int32(list, CR_RENEWTILL,
                                        creds->times.renew_till, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;
    *expiration = creds->times.endtime;

    /*
     * is_skey.  This is only in the MIT representation, not in the Heimdal
     * representation, and probably shouldn't be included.
     */
    s = webauth_attr_list_add_int32(list, CR_ISSKEY,
                                    creds->is_skey, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* Ticket flags. */
    s = webauth_attr_list_add_int32(list, CR_TICKETFLAGS,
                                    creds->ticket_flags, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* Addresses. */
    if (creds->addresses) {
        unsigned int num = 0, i;
        char name[32];
        krb5_address **temp = creds->addresses;

        while (*temp++)
            num++;
        s = webauth_attr_list_add_uint32(list, CR_NUMADDRS, num, WA_F_NONE);
        if (s != WA_ERR_NONE)
            goto cleanup;
        for (i = 0; i < num; i++) {
            snprintf(name, sizeof(name), CR_ADDRTYPE, i);
            s = webauth_attr_list_add_int32(list, name,
                                            creds->addresses[i]->addrtype,
                                            WA_F_COPY_NAME);
            if (s != WA_ERR_NONE)
                goto cleanup;
            snprintf(name, sizeof(name), CR_ADDRCONT, i);
            s = webauth_attr_list_add(list, name,
                                      creds->addresses[i]->contents,
                                      creds->addresses[i]->length,
                                      WA_F_COPY_NAME);
            if (s != WA_ERR_NONE)
                goto cleanup;
        }
    }

    /* Ticket. */
    if (creds->ticket.length) {
        s = webauth_attr_list_add(list, CR_TICKET,
                                  creds->ticket.data, creds->ticket.length,
                                  WA_F_NONE);
        if (s != WA_ERR_NONE)
            goto cleanup;
    }

    /* Second ticket. */
    if (creds->second_ticket.length) {
        s = webauth_attr_list_add(list, CR_TICKET2,
                                  creds->second_ticket.data,
                                  creds->second_ticket.length, WA_F_NONE);
        if (s != WA_ERR_NONE)
            goto cleanup;
    }

    /* Auth data. */
    if (creds->authdata) {
        unsigned int num = 0, i;
        char name[32];
        krb5_authdata **temp = creds->authdata;

        while (*temp++)
            num++;
        s = webauth_attr_list_add_uint32(list, CR_NUMAUTHDATA, num, WA_F_NONE);
        if (s != WA_ERR_NONE)
            goto cleanup;
        for (i = 0; i < num; i++) {
            snprintf(name, sizeof(name), CR_AUTHDATATYPE, i);
            s = webauth_attr_list_add_int32(list, name,
                                            creds->authdata[i]->ad_type,
                                            WA_F_COPY_NAME);
            if (s != WA_ERR_NONE)
                goto cleanup;
            snprintf(name, sizeof(name), CR_AUTHDATACONT, i);
            s = webauth_attr_list_add(list, name,
                                      creds->authdata[i]->contents,
                                      creds->authdata[i]->length,
                                      WA_F_COPY_NAME);
            if (s != WA_ERR_NONE)
                goto cleanup;
        }
    }

    /* All done.  Fill in some final details and do the attribute encoding. */
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
 * Take an externalized credential and turn it back into an internal
 * credential.  Takes the encoded credential string and its length.
 */
static int
cred_from_attr_encoding(WEBAUTH_KRB5_CTXTP *c, char *input,
                        size_t input_length, krb5_creds *creds)
{
    WEBAUTH_ATTR_LIST *list;
    int s;
    ssize_t f;
    size_t length;
    void *data;
    char *buff;

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

    /* Client principal. */
    webauth_attr_list_find(list, CR_CLIENT, &f);
    if (f != -1) {
        c->code = krb5_parse_name(c->ctx, list->attrs[f].value,
                                  &creds->client);
        if (c->code != 0) {
            s = WA_ERR_KRB5;
            goto cleanup;
        }
    }

    /* Server principal. */
    webauth_attr_list_find(list, CR_SERVER, &f);
    if (f != -1) {
        c->code = krb5_parse_name(c->ctx, list->attrs[f].value,
                                  &creds->server);
        if (c->code != 0) {
            s = WA_ERR_KRB5;
            goto cleanup;
        }
    }

    /* Keyblock. */
    creds->keyblock.magic = KV5M_KEYBLOCK;
    s = webauth_attr_list_get_int32(list, CR_KEYBLOCK_ENCTYPE,
                                    &creds->keyblock.enctype, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;
    s = webauth_attr_list_get(list, CR_KEYBLOCK_CONTENTS,
                              &data, &length, WA_F_COPY_VALUE);
    if (s != WA_ERR_NONE)
        goto cleanup;
    creds->keyblock.contents = data;
    creds->keyblock.length = length;

    /* Times */
    s = webauth_attr_list_get_int32(list, CR_AUTHTIME,
                                    &creds->times.authtime, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;
    s = webauth_attr_list_get_int32(list, CR_STARTTIME,
                                    &creds->times.starttime, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;
    s = webauth_attr_list_get_int32(list, CR_ENDTIME,
                                    &creds->times.endtime, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;
    s = webauth_attr_list_get_int32(list, CR_RENEWTILL,
                                    &creds->times.renew_till, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* is_skey.  We probably don't care about this at all. */
    s = webauth_attr_list_get_int32(list, CR_ISSKEY,
                                    (int32_t *) &creds->is_skey, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /* Ticket flags. */
    s = webauth_attr_list_get_int32(list, CR_TICKETFLAGS,
                                    &creds->ticket_flags, WA_F_NONE);
    if (s != WA_ERR_NONE)
        goto cleanup;

    /*
     * Addresses.  We may want to always ignore these.  They might not even
     * exist if we got forwardable/proxiable tickets.
     */
    webauth_attr_list_find(list, CR_NUMADDRS, &f);
    if (f != -1) {
        uint32_t num = 0;
        unsigned int i;
        char name[32];

        s = webauth_attr_list_get_uint32(list, CR_NUMADDRS, &num, WA_F_NONE);
        if (s != WA_ERR_NONE)
            goto cleanup;

        /*
         * Don't forget to add 1 to num for the null address at the end of the
         * list.
         */
        creds->addresses = calloc(num + 1, sizeof(krb5_address *));
        if (creds->addresses == NULL) {
            s = WA_ERR_NO_MEM;
            goto cleanup;
        }

        for (i = 0; i < num; i++) {
            creds->addresses[i] = malloc(sizeof(krb5_address));
            if (creds->addresses[i] == NULL)
                goto cleanup;

            creds->addresses[i]->magic = KV5M_ADDRESS;
            snprintf(name, sizeof(name), CR_ADDRTYPE, i);
            s = webauth_attr_list_get_int32(list, name,
                                            &creds->addresses[i]->addrtype,
                                            WA_F_NONE);
            if (s != WA_ERR_NONE)
                goto cleanup;
            snprintf(name, sizeof(name), CR_ADDRCONT, i);

            s = webauth_attr_list_get(list, name, &data, &length,
                                      WA_F_COPY_VALUE);
            if (s != WA_ERR_NONE)
                goto cleanup;
            creds->addresses[i]->contents = data;
            creds->addresses[i]->length = length;
        }
    }

    /* Ticket. */
    webauth_attr_list_find(list, CR_TICKET, &f);
    if (f != -1) {
        creds->ticket.magic = KV5M_DATA;
        s = webauth_attr_list_get(list, CR_TICKET, &data, &length,
                                  WA_F_COPY_VALUE);
        if (s != WA_ERR_NONE)
            goto cleanup;
        creds->ticket.data = data;
        creds->ticket.length = length;
    }

    /* Second ticket. */
    webauth_attr_list_find(list, CR_TICKET2, &f);
    if (f != -1) {
        creds->ticket.magic = KV5M_DATA;
        s = webauth_attr_list_get(list, CR_TICKET2, &data, &length,
                                  WA_F_COPY_VALUE);
        if (s != WA_ERR_NONE)
            goto cleanup;
        creds->second_ticket.data = data;
        creds->second_ticket.length = length;
    }

    /* Auth data. */
    webauth_attr_list_find(list, CR_NUMAUTHDATA, &f);
    if (f != -1) {
        uint32_t num = 0;
        unsigned int i;
        char name[32];

        s = webauth_attr_list_get_uint32(list, CR_NUMAUTHDATA, &num,
                                         WA_F_NONE);
        if (s != WA_ERR_NONE)
            goto cleanup;

        /*
         * Don't forget to add 1 to num for the null address at the end of
         * the list.
         */
        creds->authdata = calloc(num + 1, sizeof(krb5_authdata *));
        if (creds->authdata == NULL) {
            s = WA_ERR_NO_MEM;
            goto cleanup;
        }

        for (i = 0; i < num; i++) {
            creds->authdata[i] = malloc(sizeof(krb5_authdata));
            if (creds->authdata[i] == NULL)
                goto cleanup;

            creds->authdata[i]->magic = KV5M_AUTHDATA;
            snprintf(name, sizeof(name), CR_AUTHDATATYPE, i);
            s = webauth_attr_list_get_int32(list, name,
                                            &creds->authdata[i]->ad_type,
                                            WA_F_NONE);
            if (s != WA_ERR_NONE)
                goto cleanup;
            snprintf(name, sizeof(name), CR_AUTHDATACONT, i);

            s = webauth_attr_list_get(list, name, &data, &length,
                                      WA_F_COPY_VALUE);
            if (s != WA_ERR_NONE)
                goto cleanup;
            creds->authdata[i]->contents = data;
            creds->authdata[i]->length = length;
        }
    }

    s = WA_ERR_NONE;

cleanup:
    if (buff != NULL)
        free(buff);
    if (list != NULL)
        webauth_attr_list_free(list);
    if (s != WA_ERR_NONE)
        krb5_free_cred_contents(c->ctx, creds);
    return s;
}


/*
 * Create an encoded Kerberos request, including encrypted data from in_data
 * (which may be empty).  The request is stored in output in newly allocated
 * memory and the length is stored in length.  The encrypted data, if any, is
 * stored in out_data in newly alllocated memory and the length of the data is
 * stored in out_length.  Returns a WA_ERR code.
 *
 * This is used as an authenticator from a WAS to the WebKDC.
 */
int
webauth_krb5_mk_req_with_data(WEBAUTH_KRB5_CTXT *context,
                              const char *server_principal,
                              char **output, size_t *length,
                              char *in_data, size_t in_length,
                              char **out_data, size_t *out_length)
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
    if (out_data != NULL)
        *out_data = NULL;

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
        krb5_address laddr;
        char lh[4] = {127, 0, 0, 1};

        laddr.magic = KV5M_ADDRESS;
        laddr.addrtype = ADDRTYPE_INET;
        laddr.length = 4;
        laddr.contents = (void *) &lh;

        indata.data = in_data;
        indata.length = in_length;

        /*
         * We cheat here and always use localhost as the address of the remote
         * system.  This is an ugly hack, but then so is address checking, and
         * we have other security around use of the tokens.
         */
        krb5_auth_con_setflags(c->ctx, auth, 0);
        krb5_auth_con_setaddrs(c->ctx, auth, &laddr, NULL);

        c->code = krb5_mk_priv(c->ctx, auth, &indata, &outdata, NULL);
        if (c->code == 0) {
            s = WA_ERR_NONE;

            *out_data = malloc(outdata.length);
            if (*out_data == NULL)
                s = WA_ERR_NO_MEM;
            else {
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
    if (s != WA_ERR_NONE)
        if (*output != NULL)
            free(*output);
    if (auth != NULL)
        krb5_auth_con_free(c->ctx, auth);
    return s;
}


/*
 * Receive and decrypt a Kerberos request using a local keytab.  The request
 * may have associated encrypted data, which is put into out_data with
 * out_length set to the length of the data.  The principal making the remote
 * Kerberos request is stored in client_principal and the server principal to
 * which the request was addressed is stored in out_server_principal.  Returns
 * a WA_ERR code.
 */
int
webauth_krb5_rd_req_with_data(WEBAUTH_KRB5_CTXT *context,
                              const char *req, size_t length,
                              const char *keytab_path,
                              const char *server_principal,
                              char **out_server_principal,
                              char **client_principal,
                              int local, char *in_data, size_t in_length,
                              char **out_data, size_t *out_length)
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

    if (out_server_principal != NULL)
        *out_server_principal = NULL;

    buf.data = (char *) req;
    buf.length = length;
    c->code = krb5_rd_req(c->ctx, &auth, &buf, server, keytab, NULL, NULL);
    if (c->code == 0) {
        if (out_server_principal != NULL)
            krb5_unparse_name(c->ctx, server, out_server_principal);
        if (auth != NULL) {
            krb5_authenticator *ka;

            c->code = krb5_auth_con_getauthenticator(c->ctx, auth, &ka);
            if (c->code != 0)
                *client_principal = NULL;
            else {
                int local_ok = 0;

                if (local) {
                    krb5_error_code tcode;
                    char lname[256];

                    tcode = krb5_aname_to_localname(c->ctx, ka->client,
                                                    sizeof(lname) - 1,
                                                    lname);
                    if (tcode == 0) {
                        *client_principal = strdup(lname);
                        if (*client_principal == NULL) {
                            krb5_free_authenticator(c->ctx, ka);
                            krb5_auth_con_free(c->ctx, auth);
                            s = WA_ERR_NO_MEM;
                            goto done;
                        }
                        local_ok = 1;
                    }
                }

                if (!local_ok)
                    c->code = krb5_unparse_name(c->ctx, ka->client,
                                                client_principal);

                if (in_data != NULL && out_data != NULL) {
                    krb5_data inbuf, outbuf;
                    krb5_address raddr;
                    char rh[4] = {127, 0, 0, 1};

                    raddr.magic = KV5M_ADDRESS;
                    raddr.addrtype = ADDRTYPE_INET;
                    raddr.length = 4;
                    raddr.contents = (void *) &rh;

                    /*
                     * We cheat and always use 127.0.0.1 as the address, which
                     * is what the remote side also always sends.  We use
                     * encryption of tokens to protect the request.
                     */
                    inbuf.data = in_data;
                    inbuf.length = in_length;
                    krb5_auth_con_setflags(c->ctx, auth, 0);
                    krb5_auth_con_setaddrs(c->ctx, auth, NULL, &raddr);
                    c->code = krb5_rd_priv(c->ctx, auth,
                                           &inbuf, &outbuf, NULL);
                    if (c->code == 0) {
                        *out_data = malloc(outbuf.length);
                        if (*out_data == NULL)
                            s = WA_ERR_NO_MEM;
                        else {
                            s = WA_ERR_NONE;
                            *out_length = outbuf.length;
                            memcpy(*out_data, outbuf.data, outbuf.length);
                        }
                        krb5_free_data_contents(c->ctx, &outbuf);
                    }

                }
                krb5_free_authenticator(c->ctx, ka);
            }
            krb5_auth_con_free(c->ctx, auth);
        }
    }

done:
    krb5_kt_close(c->ctx, keytab);
    krb5_free_principal(c->ctx, server);
    if (s == WA_ERR_NONE && c->code != 0)
        s = WA_ERR_KRB5;
    if (s != WA_ERR_NONE)
        if (out_server_principal && *out_server_principal != NULL)
            free(*out_server_principal);
    return s;
}


/*
 * Export a TGT into an encoded credential that can be put into a token.
 * Stores the resulting encoded credential in tgt and its length in tgt_len.
 * The lifetime of the credential will be stored in expiration.  Returns a
 * WA_ERR code.
 */
int
webauth_krb5_export_tgt(WEBAUTH_KRB5_CTXT *context,
                        char **tgt, size_t *tgt_len, time_t *expiration)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    krb5_principal tgtprinc, client;
    krb5_data *client_realm;
    krb5_creds creds, tgtq;
    int s;

    assert(c != NULL);
    assert(tgt != NULL);
    assert(tgt_len != NULL);
    assert(expiration != NULL);

    /* First we need to find the TGT in the ticket cache. */
    c->code = krb5_cc_get_principal(c->ctx, c->cc, &client);
    if (c->code != 0)
        return WA_ERR_KRB5;
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

    c->code = krb5_cc_retrieve_cred(c->ctx, c->cc,
                                    KRB5_TC_MATCH_SRV_NAMEONLY,
                                    &tgtq, &creds);

    if (c->code == 0) {
        s = cred_to_attr_encoding(c, &creds, tgt, tgt_len, expiration);
        krb5_free_cred_contents(c->ctx, &creds);
    } else
        s = WA_ERR_KRB5;

    krb5_free_principal(c->ctx, client);
    krb5_free_principal(c->ctx, tgtprinc);

    return s;
}
