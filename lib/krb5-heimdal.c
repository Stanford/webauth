/*
 * Heimdal Kerberos interface for WebAuth.
 *
 * This file is *included* (via the preprocessor) in krb5.c for systems that
 * use Heimdal Kerberos.  If you make any changes here, you probably also need
 * to make a corresponding change to krb5-mit.c for systems with MIT Kerberos.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2002, 2003, 2006, 2009, 2010, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

/*
 * Take a single Kerberos credential and serialize it into a buffer, using the
 * encoding required for putting it into tokens.  output will be a pointer to
 * newly allocated memory, and length will be set to the encoded length.
 * expiration will be set to the expiration time of the ticket.  Returns a
 * WA_ERR code.
 */
static int
encode_creds(struct webauth_context *ctx, struct webauth_krb5 *kc,
             krb5_creds *creds, void **output, size_t *length,
             time_t *expiration)
{
    int status;
    struct webauth_krb5_cred data;

    /* Start by copying the credential data into our standard struct. */
    memset(&data, 0, sizeof(data));
    status = encode_principal(ctx, kc, creds->client, &data.client_principal);
    if (status != WA_ERR_NONE)
        return status;
    status = encode_principal(ctx, kc, creds->server, &data.server_principal);
    if (status != WA_ERR_NONE)
        return status;
    data.keyblock_enctype  = creds->session.keytype;
    data.keyblock_data     = creds->session.keyvalue.data;
    data.keyblock_data_len = creds->session.keyvalue.length;
    data.auth_time         = creds->times.authtime;
    data.start_time        = creds->times.starttime;
    data.end_time          = creds->times.endtime;
    if (expiration != NULL)
        *expiration = creds->times.endtime;
    data.renew_until       = creds->times.renew_till;
    data.flags             = creds->flags.i;
    if (creds->addresses.len > 0) {
        size_t i, size;

        data.address_count = creds->addresses.len;
        size = creds->addresses.len * sizeof(struct webauth_krb5_cred_address);
        data.address = apr_palloc(kc->pool, size);
        for (i = 0; i < creds->addresses.len; i++) {
            data.address[i].type = creds->addresses.val[i].addr_type;
            data.address[i].data = creds->addresses.val[i].address.data;
            data.address[i].data_len = creds->addresses.val[i].address.length;
        }
    }
    if (creds->ticket.length > 0) {
        data.ticket     = creds->ticket.data;
        data.ticket_len = creds->ticket.length;
    }
    if (creds->second_ticket.length > 0) {
        data.second_ticket     = creds->second_ticket.data;
        data.second_ticket_len = creds->second_ticket.length;
    }
    if (creds->authdata.len > 0) {
        size_t i, size;

        data.authdata_count = creds->authdata.len;
        size = creds->authdata.len * sizeof(struct webauth_krb5_cred_authdata);
        data.authdata = apr_palloc(kc->pool, size);
        for (i = 0; i < creds->authdata.len; i++) {
            data.authdata[i].type = creds->authdata.val[i].ad_type;
            data.authdata[i].data = creds->authdata.val[i].ad_data.data;
            data.authdata[i].data_len = creds->authdata.val[i].ad_data.length;
        }
    }

    /* All done.  Do the attribute encoding. */
    return webauth_encode(ctx, kc->pool, wai_krb5_cred_encoding, &data,
                          output, length);
}


/*
 * Take a serialized Kerberos credential and decode it into a krb5_creds
 * structure.  creds will point to newly-allocated pool memory.
 *
 * Be very cautious of memory management here.  Nearly all of the credential
 * structure will be allocated from pool memory, and therefore the credential
 * must not be freed with the normal Kerberos memory calls.  However, the
 * client and server principals will be allocated by the Kerberos library and
 * will need to be freed.
 */
static int
decode_creds(struct webauth_context *ctx, struct webauth_krb5 *kc,
             const void *input, size_t length, krb5_creds *creds)
{
    void *buf;
    WEBAUTH_ATTR_LIST *alist = NULL;
    struct webauth_krb5_cred data;
    int status;
    size_t size, i;

    /* Decode the input into an attribute list. */
    buf = apr_pmemdup(kc->pool, input, length);
    status = webauth_attrs_decode(buf, length, &alist);
    if (status != WA_ERR_NONE) {
        webauth_error_set(ctx, status, "credential decode failed");
        return status;
    }

    /*
     * Decode the attribute list and copy the results into the credential
     * struct.  is_skey is not supported by Heimdal, so ignore it.
     */
    memset(&data, 0, sizeof(data));
    status = webauth_decode(ctx, kc->pool, wai_krb5_cred_encoding, input,
                            length, &data);
    if (status != WA_ERR_NONE) {
        webauth_attr_list_free(alist);
        return status;
    }
    webauth_attr_list_free(alist);
    memset(creds, 0, sizeof(krb5_creds));
    if (data.client_principal != NULL) {
        status = decode_principal(ctx, kc, data.client_principal,
                                  &creds->client);
        if (status != WA_ERR_NONE)
            return status;
    }
    if (data.client_principal != NULL) {
        status = decode_principal(ctx, kc, data.server_principal,
                                  &creds->server);
        if (status != WA_ERR_NONE)
            return status;
    }
    creds->session.keytype = data.keyblock_enctype;
    creds->session.keyvalue.data = data.keyblock_data;
    creds->session.keyvalue.length = data.keyblock_data_len;
    creds->times.authtime = data.auth_time;
    creds->times.starttime = data.start_time;
    creds->times.endtime = data.end_time;
    creds->times.renew_till = data.renew_until;
    creds->flags.i = data.flags;
    if (data.address_count > 0) {
        creds->addresses.len = data.address_count;
        size = data.address_count * sizeof(krb5_address);
        creds->addresses.val = apr_pcalloc(kc->pool, size);
        for (i = 0; i < data.address_count; i++) {
            creds->addresses.val[i].addr_type = data.address[i].type;
            creds->addresses.val[i].address.data = data.address[i].data;
            creds->addresses.val[i].address.length = data.address[i].data_len;
        }
    }
    if (data.ticket != NULL) {
        creds->ticket.data = data.ticket;
        creds->ticket.length = data.ticket_len;
    }
    if (data.second_ticket != NULL) {
        creds->second_ticket.data = data.second_ticket;
        creds->second_ticket.length = data.second_ticket_len;
    }
    if (data.authdata_count > 0) {
        creds->authdata.len = data.authdata_count;
        size = data.authdata_count * sizeof(*creds->authdata.val);
        creds->authdata.val = apr_palloc(kc->pool, size);
        for (i = 0; i < data.authdata_count; i++) {
            creds->authdata.val[i].ad_type = data.authdata[i].type;
            creds->authdata.val[i].ad_data.data = data.authdata[i].data;
            creds->authdata.val[i].ad_data.length = data.authdata[i].data_len;
        }
    }
    return WA_ERR_NONE;
}
