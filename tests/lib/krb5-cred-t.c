/*
 * Test suite for libwebauth Kerberos credential import.
 *
 * Tests importing pre-generated credentials that are part of the package test
 * data, which means that it can run without a Kerberos configuration.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <tests/tap/basic.h>
#include <tests/tap/string.h>
#include <webauth/basic.h>
#include <webauth/krb5.h>

/* MIT doesn't provide this typedef. */
#ifdef HAVE_KRB5_MIT
typedef krb5_address **krb5_addresses;
#endif

/*
 * How to reference addresses, whether addresses are present, and how to free
 * them.  This has to be done differently in MIT and Heimdal since the data
 * structures they use for addresses are much different.
 */
#ifdef HAVE_KRB5_MIT
# define ADDRESSES(data)        (data->addresses)
# define HAS_ADDRESSES(data)    (data->addresses != NULL)
# define FREE_ADDRESSES(data)                                   \
    do {                                                        \
        if (data->addresses != NULL)                            \
            krb5_free_addresses(data->ctx, data->addresses);    \
    } while (0)
#else
# define ADDRESSES(data)        (&data->addresses)
# define HAS_ADDRESSES(data)    (data->addresses.len > 0)
# define FREE_ADDRESSES(data)                                   \
    do {                                                        \
        krb5_free_addresses(data->ctx, &data->addresses);       \
    } while (0)
#endif

/*
 * Three addresses that we use for testing.  The first IPv4 address is the one
 * in tests/data/creds/service, the second is in tests/data/creds/addresses,
 * and the third is the IPv6 address in tests/data/creds/addresses.
 */
static const unsigned char test_addr1_data[4] = { 171, 67, 24, 175 };
static const unsigned char test_addr2_data[4] = { 171, 67, 225, 134 };
static const unsigned char test_addr3_data[16] = {
    0x26, 0x07, 0xf6, 0xd0, 0x00, 0x00, 0xa2, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65
};

/* Build krb5_address structs, which are different across implementations. */
#ifdef HAVE_KRB5_MIT
static const krb5_address test_addr1 = {
    KV5M_ADDRESS, ADDRTYPE_INET, 4, (unsigned char *) test_addr1_data
};
static const krb5_address test_addr2 = {
    KV5M_ADDRESS, ADDRTYPE_INET, 4, (unsigned char *) test_addr2_data
};
static const krb5_address test_addr3 = {
    KV5M_ADDRESS, ADDRTYPE_INET6, 16, (unsigned char *) test_addr3_data
};
#else
static const krb5_address test_addr1 = {
    KRB5_ADDRESS_INET, { 4, (void *) test_addr1_data }
};
static const krb5_address test_addr2 = {
    KRB5_ADDRESS_INET, { 4, (void *) test_addr2_data }
};
static const krb5_address test_addr3 = {
    KRB5_ADDRESS_INET6, { 16, (void *) test_addr3_data }
};
#endif

/*
 * Holds Kerberos credential data that we can use in the test.  We
 * intentionally don't extract difficult things like the actual ticket.  This
 * is a separate struct so that we can write two different functions to
 * extract the data from either MIT or Heimdal into a consistent structure.
 */
struct cred_data {
    krb5_context ctx;
    char *client;
    char *server;
    time_t endtime;
    time_t renew_till;
    bool forwardable;
    krb5_enctype enctype;
    krb5_addresses addresses;
};

#define CHECK(ctx, s, m) check_status((ctx), (s), (m), __FILE__, __LINE__)
#define CHECK_BAIL(ctx, s) bail_status((ctx), (s), __FILE__, __LINE__)


/*
 * Check the status of a WebAuth call.
 */
static void
check_status(struct webauth_context *ctx, int s, const char *message,
             const char *file, unsigned long line)
{
    if (s != WA_ERR_NONE)
        diag("webauth call failed at %s line %lu: %s (%d)\n", file, line,
             webauth_error_message(ctx, s), s);
    is_int(s, WA_ERR_NONE, "%s", message);
}


/*
 * The same, but call bail if the WebAuth call fails.
 */
static void
bail_status(struct webauth_context *ctx, int s, const char *file,
            unsigned long line)
{
    if (s != WA_ERR_NONE)
        bail("webauth call failed at %s line %lu: %s (%d)\n", file, line,
             webauth_error_message(ctx, s), s);
}


/*
 * Extract implementation-specific data from a credential structure.  There
 * are some parts of the credential structure that are named differently based
 * on whether the implementation is MIT or Heimdal.
 */
#if defined(HAVE_KRB5_MIT)

static void
extract_cred_data_impl(krb5_context ctx, krb5_creds *cred,
                       struct cred_data *data)
{
    data->forwardable = (cred->ticket_flags & TKT_FLG_FORWARDABLE) != 0;
    data->enctype = cred->keyblock.enctype;
    if (cred->addresses != NULL && cred->addresses[0] != NULL)
        krb5_copy_addresses(ctx, cred->addresses, &data->addresses);
}

#else

static void
extract_cred_data_impl(krb5_context ctx, krb5_creds *cred,
                       struct cred_data *data)
{
    data->forwardable = (cred->flags.i & KDC_OPT_FORWARDABLE) != 0;
    data->enctype = cred->session.keytype;
    if (cred->addresses.len > 0)
        krb5_copy_addresses(ctx, &cred->addresses, &data->addresses);
}

#endif


/*
 * Given a krb5_creds structure, extract data from it into a newly-allocated
 * cred_data structure and return the new structure.
 */
static struct cred_data *
extract_cred_data(krb5_context ctx, krb5_creds *cred)
{
    struct cred_data *data;
    char *principal;

    data = bcalloc(1, sizeof(struct cred_data));
    data->ctx = ctx;
    if (krb5_unparse_name(ctx, cred->client, &principal) == 0) {
        data->client = bstrdup(principal);
        krb5_free_unparsed_name(ctx, principal);
    }
    if (krb5_unparse_name(ctx, cred->server, &principal) == 0) {
        data->server = bstrdup(principal);
        krb5_free_unparsed_name(ctx, principal);
    }
    data->endtime = cred->times.endtime;
    data->renew_till = cred->times.renew_till;
    extract_cred_data_impl(ctx, cred, data);
    return data;
}


/*
 * Free a cred_data structure.
 */
static void
free_cred_data(struct cred_data *data)
{
    free(data->server);
    free(data->client);
    FREE_ADDRESSES(data);
    krb5_free_context(data->ctx);
    free(data);
}


/*
 * Given the path to a test credential and the credential included in it,
 * create a new WebAuth Kerberos context and initialize it from that test
 * credential.  Then, find the credential in the ticket cache and read the
 * Kerberos credential from it.  Returns the new WebAuth Kerberos context.
 */
static struct cred_data *
import_cred(struct webauth_context *ctx, const char *file)
{
    char *path, *tmpdir, *cache, *message;
    FILE *input;
    char buffer[BUFSIZ];
    size_t size;
    int s;
    struct webauth_krb5 *kc;
    krb5_context krb5_ctx;
    krb5_ccache cc;
    krb5_cc_cursor cursor;
    krb5_creds cred;
    krb5_error_code code;
    struct cred_data *data;

    /* Read the encoded token. */
    path = test_file_path(file);
    if (path == NULL)
        sysbail("cannot find %s", file);
    input = fopen(path, "r");
    if (input == NULL)
        sysbail("cannot open %s", path);
    size = fread(buffer, 1, sizeof(buffer), input);
    if (ferror(input))
        sysbail("cannot read %s", path);
    fclose(input);

    /* Import the credential and create a ticket cache. */
    tmpdir = test_tmpdir();
    basprintf(&cache, "%s/krb5cc_import", tmpdir);
    s = webauth_krb5_new(ctx, &kc);
    CHECK_BAIL(ctx, s);
    basprintf(&message, "import %s cred", file);
    s = webauth_krb5_import_cred(ctx, kc, buffer, size, cache);
    CHECK(ctx, s, message);
    free(message);

    /* Create a Kerberos context and pull the credential from the cache. */
    memset(&cred, 0, sizeof(cred));
    code = krb5_init_context(&krb5_ctx);
    if (code != 0)
        bail("cannot create Kerberos context");
    code = krb5_cc_resolve(krb5_ctx, cache, &cc);
    is_int(0, code, "... open Kerberos ticket cache");
    code = krb5_cc_start_seq_get(krb5_ctx, cc, &cursor);
    if (code != 0)
        bail("cannot create cursor on ticket cache");
    code = krb5_cc_next_cred(krb5_ctx, cc, &cursor, &cred);
    is_int(0, code, "... read first ticket");
    krb5_cc_end_seq_get(krb5_ctx, cc, &cursor);
    krb5_cc_close(krb5_ctx, cc);

    /* Extract credential data into our own struct. */
    data = extract_cred_data(krb5_ctx, &cred);
    krb5_free_cred_contents(krb5_ctx, &cred);

    /* Clean up and return. */
    test_file_path_free(path);
    free(cache);
    test_tmpdir_free(tmpdir);
    return data;
}


int
main(void)
{
    struct webauth_context *ctx;
    struct cred_data *data;

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    plan(63);

    /* Basic credential with nothing special. */
    data = import_cred(ctx, "data/creds/basic");
    is_string("thoron@heimdal.stanford.edu", data->client,
              "... client principal");
    is_string("krbtgt/heimdal.stanford.edu@heimdal.stanford.edu",
              data->server, "... server principal");
    is_int(1355447711, data->endtime, "... end time");
    is_int(0, data->renew_till, "... not renewable");
    ok(!data->forwardable, "... not forwardable");
    is_int(ENCTYPE_AES256_CTS_HMAC_SHA1_96, data->enctype,
           "... session enctype");
    ok(!HAS_ADDRESSES(data), "... no addresses");
    free_cred_data(data);

    /* Forwardable and renewable credential. */
    data = import_cred(ctx, "data/creds/renewable");
    is_string("thoron@heimdal.stanford.edu", data->client,
              "... client principal");
    is_string("krbtgt/heimdal.stanford.edu@heimdal.stanford.edu",
              data->server, "... server principal");
    is_int(1355529261, data->endtime, "... end time");
    is_int(1356047658, data->renew_till, "... renew until time");
    ok(data->forwardable, "... forwardable");
    is_int(ENCTYPE_AES256_CTS_HMAC_SHA1_96, data->enctype,
           "... session enctype");
    ok(!HAS_ADDRESSES(data), "... no addresses");
    free_cred_data(data);

    /* Service ticket with restricted enctypes and address. */
    data = import_cred(ctx, "data/creds/service");
    is_string("thoron@heimdal.stanford.edu", data->client,
              "... client principal");
    is_string("host/example.stanford.edu@heimdal.stanford.edu",
              data->server, "... server principal");
    is_int(1355529505, data->endtime, "... end time");
    is_int(1356047903, data->renew_till, "... renew until time");
    ok(data->forwardable, "... forwardable");
    is_int(ENCTYPE_DES3_CBC_SHA1, data->enctype, "... session enctype");
    ok(HAS_ADDRESSES(data), "... addresses are present");
    ok(krb5_address_search(data->ctx, &test_addr1, ADDRESSES(data)),
       "... found expected IPv4 address");
    free_cred_data(data);

    /* Ticket with multiple addresses. */
    data = import_cred(ctx, "data/creds/addresses");
    is_string("thoron@heimdal.stanford.edu", data->client,
              "... client principal");
    is_string("krbtgt/heimdal.stanford.edu@heimdal.stanford.edu",
              data->server, "... server principal");
    is_int(1355532627, data->endtime, "... end time");
    is_int(1356051022, data->renew_till, "... renew until time");
    ok(data->forwardable, "... forwardable");
    is_int(ENCTYPE_AES256_CTS_HMAC_SHA1_96, data->enctype,
           "... session enctype");
    ok(HAS_ADDRESSES(data), "... addresses are present");
    ok(krb5_address_search(data->ctx, &test_addr2, ADDRESSES(data)),
       "... found expected IPv4 address");
    ok(krb5_address_search(data->ctx, &test_addr3, ADDRESSES(data)),
       "... found expected IPv6 address");
    free_cred_data(data);

    /* Active Directory ticket encoded using Heimdal libraries. */
    data = import_cred(ctx, "data/creds/ad-heimdal");
    is_string("thoron@NT.STANFORD.EDU", data->client,
              "... client principal");
    is_string("krbtgt/NT.STANFORD.EDU@NT.STANFORD.EDU",
              data->server, "... server principal");
    is_int(1355559675, data->endtime, "... end time");
    is_int(1356074475, data->renew_till, "... renew until time");
    ok(data->forwardable, "... forwardable");
    is_int(ENCTYPE_AES256_CTS_HMAC_SHA1_96, data->enctype,
           "... session enctype");
    ok(!HAS_ADDRESSES(data), "... no addresses");
    free_cred_data(data);

    /* Heimdal ticket with the old encoding (reversed flag bits). */
    data = import_cred(ctx, "data/creds/old-heimdal");
    is_string("thoron@heimdal.stanford.edu", data->client,
              "... client principal");
    is_string("krbtgt/heimdal.stanford.edu@heimdal.stanford.edu",
              data->server, "... server principal");
    is_int(1355556533, data->endtime, "... end time");
    is_int(1356074930, data->renew_till, "... renew until time");
    ok(data->forwardable, "... forwardable");
    is_int(ENCTYPE_AES256_CTS_HMAC_SHA1_96, data->enctype,
           "... session enctype");
    ok(!HAS_ADDRESSES(data), "... no addresses");
    free_cred_data(data);

    /* Clean up. */
    webauth_context_free(ctx);
    return 0;
}
