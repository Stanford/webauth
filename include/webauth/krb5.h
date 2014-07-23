/*
 * WebAuth Kerberos authentication and encryption functions.
 *
 * These functions encapsulate the WebAuth support for Kerberos, including
 * creating a WebAuth Kerberos context from various sources of authentication,
 * constructing and verifying Kerberos authenticators, and encrypting and
 * decrypting data protected by Kerberos session keys.  Also included are
 * functions to export and import Kerberos tickets.
 *
 * All of these functions will eventually become internal to the WebAuth
 * library once higher-level functions have been added to perform WebAuth
 * protocol actions.
 *
 * Written by Russ Allbery
 * Copyright 2002, 2003, 2008, 2009, 2010, 2011, 2012, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef WEBAUTH_KRB5_H
#define WEBAUTH_KRB5_H 1

#include <webauth/defines.h>

struct webauth_context;
struct webauth_krb5;

/* Supported protocols for Kerberos password change. */
enum webauth_change_protocol {
    WA_CHANGE_KPASSWD = 0,
    WA_CHANGE_REMCTL  = 1
};

/*
 * Configuration information for Kerberos password change operations.  This is
 * used to bundle together the configuration parameters and pass them into
 * webauth_krb5_change_config.  If the protocol is WA_CHANGE_KPASSWD, all the
 * other fields are ignored.
 *
 * The port may be 0, which indicates the standard port should be used.
 * identity is the identity of the password change service and may be NULL to
 * use the default.  command and subcommand are protocol-specific command
 * information, such as the first two arguments to a remctl command.
 *
 * The timeout will only be enforced if the library is built with remctl 3.1
 * or later (which have remctl_set_timeout).
 */
struct webauth_krb5_change_config {
    enum webauth_change_protocol protocol;
    const char *host;
    unsigned short port;        /* May be 0 to use the standard port */
    const char *identity;       /* Metadata service identity or NULL */
    const char *command;        /* Protocol-specific command */
    const char *subcommand;     /* Protocol-specific subcommand */
    time_t timeout;             /* Network timeout, or 0 for no timeout */
};

/* Flags for webauth_krb5_get_principal and webauth_krb5_read_auth. */
enum webauth_krb5_canon {
    WA_KRB5_CANON_NONE  = 0,    /* Do not canonicalize principals. */
    WA_KRB5_CANON_LOCAL = 1,    /* Strip the local realm */
    WA_KRB5_CANON_STRIP = 2     /* Strip any realm */
};

BEGIN_DECLS

/*
 * Create new webauth krb5 context for use with all the webauth_krb5_* calls.
 * Takes the webauth_context with which to associate it and a pointer to a
 * webauth_krb5 struct.  The contents of that struct will be overwritten
 * without freeing, so it does not have to be initialized (but should be freed
 * if being reused).
 *
 * The initialized context can be freed with webauth_krb5_free.  It will be
 * automatically freed if the pool associated with the webauth_context is
 * freed.
 */
int webauth_krb5_new(struct webauth_context *, struct webauth_krb5 **)
    __attribute__((__nonnull__));

/*
 * Frees the webauth_krb5 context including any memory allocated within that
 * context.  If this context has an associated credential cache, that cache
 * will be destroyed as well.  This will be done automatically when the
 * associated webauth_context is destroyed, so it's normally not necessary to
 * call this function.
 */
void webauth_krb5_free(struct webauth_context *, struct webauth_krb5 *)
    __attribute__((__nonnull__));

/*
 * Configure the path to a credential cache to use for FAST armor during
 * password authentication requests, or NULL to disable use of FAST armor.  If
 * this is set, FAST will be used and required for all password
 * authentications, and Kerberos authentications will fail if FAST cannot be
 * used.
 */
int webauth_krb5_set_fast_armor_path(struct webauth_context *,
                                     struct webauth_krb5 *,
                                     const char *)
    __attribute__((__nonnull__(1, 2)));

/*
 * Initialize a webauth_krb5 context from an existing ticket cache.  If the
 * provided cache name is NULL, krb5_cc_default is used.
 */
int webauth_krb5_init_via_cache(struct webauth_context *,
                                struct webauth_krb5 *,
                                const char *cache)
    __attribute__((__nonnull__(1, 2)));

/*
 * Initialize a webauth_krb5 context with a keytab, obtaining a TGT.
 * Credentials will be placed in the specified cache, or a memory cache if
 * cache is NULL.  If server_principal is NULL, the first principal in the
 * keytab will be used; otherwise, the specifed server principal will be used.
 */
int webauth_krb5_init_via_keytab(struct webauth_context *,
                                 struct webauth_krb5 *,
                                 const char *keytab,
                                 const char *server_principal,
                                 const char *cache)
    __attribute__((__nonnull__(1, 2, 3)));

/*
 * Initialize a webauth_krb5 context with a username and password, obtaining
 * credentials for the principal specified via get_principal, or a TGT for the
 * default realm if that argument is NULL.  Normally, the only argument used
 * other than NULL is "kadmin/changepw" for password changes.
 *
 * If a TGT is obtained, it is verified using the specified keytab if
 * provided.  If the keytab is NULL, the TGT will not be verified.  The
 * obtained ticket will be placed in the specified cache or in a memory cache
 * if cache is NULL.
 *
 * server_principal_out will be set to the fully qualified server principal
 * used, unless the keytab is NULL.
 */
int webauth_krb5_init_via_password(struct webauth_context *,
                                   struct webauth_krb5 *,
                                   const char *username, const char *password,
                                   const char *get_principal,
                                   const char *keytab,
                                   const char *server_principal,
                                   const char *cache,
                                   char **server_principal_out)
    __attribute__((__nonnull__(1, 2, 3, 4)));

/*
 * Initialize a context from a credential created via webauth_krb5_export_cred
 * without importing the credential.  This is used to prep the ticket cache
 * when some actions have to be taken between preparation of the cache and
 * storing tickets in it.  Currently, this is only used in special handling
 * for keyring caches.
 */
int webauth_krb5_prepare_via_cred(struct webauth_context *,
                                  struct webauth_krb5 *,
                                  const void *cred, size_t cred_len,
                                  const char *cache)
    __attribute__((__nonnull__));


/*
 * Export a credential from a context.  The context must have previously been
 * initialized with webauth_krb5_init_via_* or webauth_krb5_import_cred.
 * Takes the principal for which to export a service ticket.  If this value is
 * NULL, the TGT is exported.  The provided time_t value is set to the
 * expiration time of the credentials.
 */
int webauth_krb5_export_cred(struct webauth_context *, struct webauth_krb5 *,
                             const char *principal,
                             void **cred, size_t *cred_len,
                             time_t *expiration)
    __attribute__((__nonnull__(1, 2, 4, 5)));

/*
 * Import a credential (TGT or ticket) that was exported via
 * webauth_krb5_export_cred.  If the webauth_krb5 context has not yet been
 * initialized, it will be initialized using the provided ticket cache
 * identifier.  If the cache parameter is NULL and the context is not yet
 * initialized, a memory cache will be used.
 */
int webauth_krb5_import_cred(struct webauth_context *, struct webauth_krb5 *,
                             const void *, size_t, const char *cache)
    __attribute__((__nonnull__(1, 2, 3)));

/*
 * Get the string form of the principal from the context.  This should only be
 * called after a successful call to webauth_krb5_init_via_* or
 * webauth_krb5_import_cred.
 *
 * If the canon argument is WA_KRB5_CANON_LOCAL, krb5_aname_to_localname is
 * called on the principal.  If krb5_aname_to_localname returns an error, the
 * fully-qualified principal name is returned.
 *
 * If the canon argument is WA_KRB5_CANON_STRIP, the realm is stripped,
 * regardless of what it is.
 *
 * If the canon argument is WA_KRB5_CANON_NONE, the fully-qualified Kerberos
 * principal is always returned.
 */
int webauth_krb5_get_principal(struct webauth_context *, struct webauth_krb5 *,
                               char **principal, enum webauth_krb5_canon)
    __attribute__((__nonnull__));

/*
 * Get the ticket cache from the context.  This is the string suitable for
 * storing in KRB5CCNAME.  It should only be called after a successful call to
 * webauth_krb5_init_via_* or webauth_krb5_import_cred.
 */
int webauth_krb5_get_cache(struct webauth_context *, struct webauth_krb5 *,
                           char **)
    __attribute__((__nonnull__));

/*
 * Get the realm from the context.  This should only be called after a
 * successful call to webauth_krb5_init_via_* or webauth_krb5_import_cred.
 */
int webauth_krb5_get_realm(struct webauth_context *, struct webauth_krb5 *,
                           char **)
    __attribute__((__nonnull__));

/*
 * Calls krb5_mk_req using the specified service and stores the resulting
 * authenticated request in req, which should be freed when it is no longer
 * needed.  This should only be called after one of the
 * webauth_krb5_init_via_* or webauth_krb5_import_cred functions has been
 * successfully called.
 */
int webauth_krb5_make_auth(struct webauth_context *, struct webauth_krb5 *,
                           const char *server_principal,
                           void **req, size_t *length)
    __attribute__((__nonnull__));

/*
 * The same as webauth_krb5_make_auth, but also encrypt the provided data
 * in the session key.
 */
int webauth_krb5_make_auth_data(struct webauth_context *,
                                struct webauth_krb5 *,
                                const char *server_principal,
                                void **req, size_t *length,
                                const void *in_data, size_t in_length,
                                void **out_data, size_t *out_length)
    __attribute__((__nonnull__(1, 2, 3, 4, 5)));

/*
 * Calls krb5_rd_req on the specified request and returns the client
 * principal.  If server_principal is NULL, the first principal in the keytab
 * will be used; otherwise, the specifed server principal will be used.
 */
int webauth_krb5_read_auth(struct webauth_context *, struct webauth_krb5 *,
                           const void *req, size_t length,
                           const char *keytab, const char *server_principal,
                           char **client_principal,
                           enum webauth_krb5_canon)
    __attribute__((__nonnull__(1, 2, 3, 5, 7)));

/*
 * The same as webauth_krb5_read_auth, but also decrypts the provided secure
 * data with the session key.
 */
int webauth_krb5_read_auth_data(struct webauth_context *,
                                struct webauth_krb5 *, const void *req,
                                size_t length, const char *keytab,
                                const char *server_principal,
                                char **out_server_princ,
                                char **client_principal,
                                enum webauth_krb5_canon,
                                const void *in_data, size_t in_length,
                                void **out_data, size_t *out_length)
    __attribute__((__nonnull__(1, 2, 3, 5, 8)));

/*
 * Configure how password changes using this webauth_krb5 struct will be
 * done.
 */
int webauth_krb5_change_config(struct webauth_context *,
                               struct webauth_krb5 *,
                               struct webauth_krb5_change_config *)
    __attribute__((__nonnull__));

/*
 * Change the password for a principal.  The webauth_krb5 context must already
 * be initialized using webauth_krb5_init_via_password with credentials for
 * the password change service (normally kadmin/changepw).
 *
 * The password change will be done using the configuration set with
 * webauth_krb5_change_config if it is called (on the same webauth_krb5
 * struct) prior to making this call.
 */
int webauth_krb5_change_password(struct webauth_context *,
                                 struct webauth_krb5 *, const char *password)
    __attribute__((__nonnull__));


END_DECLS

#endif /* !WEBAUTH_KRB5_H */
