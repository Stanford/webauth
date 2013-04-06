/*
 * Internal definitions and prototypes for Apache WebAuth LDAP module.
 *
 * Written by Anton Ushakov
 * Copyright 2003, 2005, 2006, 2007, 2009, 2010, 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#ifndef MOD_WEBAUTHLDAP_H
#define MOD_WEBAUTHLDAP_H

#include <config-mod.h>
#include <portable/stdbool.h>

#if HAVE_INTTYPES_H
# include <inttypes.h>
#elif HAVE_STDINT_H
# include <stdint.h>
#endif

#include <apr_tables.h>         /* apr_array_header_t */
#include <apr_thread_mutex.h>
#include <httpd.h>              /* server_rec, request_rec, command_rec */

/* Command table provided by the configuration handling code. */
extern const command_rec webauthldap_cmds[];

/* constants */
#define LDAP_SIZELIMIT -1
#define PRIVGROUP_DIRECTIVE "privgroup"
#define DN_ATTRIBUTE "dn"
#define MAX_LDAP_CONN 16
#define FILTER_MATCH "USER"

/* environment variables */
#define ENV_KRB5_TICKET "KRB5CCNAME"

/* defaults struct passed to SASL */
typedef struct {
    const char *mech;
    char *realm;
    char *authcid;
    char *passwd;
    char *authzid;
} MWAL_SASL_DEFAULTS;

/*
 * Server configuration.  For parameters where there's no obvious designated
 * value for when the directive hasn't been set, there's a corresponding _set
 * variable that holds whether that directive is set in a particular scope.
 */
struct server_config {
    const char *auth_attr;
    bool authrule;
    const char *base;
    const char *binddn;
    bool debug;
    const char *filter;
    const char *host;
    const char *keytab_path;
    const char *keytab_principal;
    unsigned long port;
    const char *separator;
    bool ssl;
    const char *tktcache;

    /* Only used during configuration merging. */
    bool authrule_set;
    bool debug_set;
    bool filter_set;
    bool ssl_set;

    /*
     * These aren't part of the Apache configuration, but they are loaded as
     * part of reading the configuration, are global to the module, and need
     * to be reset when the module is reloaded, so we store them here.
     */
    int ldapversion;
    int scope;
    int ldcount;
    apr_array_header_t *ldarray;
    apr_thread_mutex_t *ldmutex;
    apr_thread_mutex_t *totalmutex;
};

/* The same, but for the directory configuration. */
struct dir_config {
    apr_array_header_t *attribs;        /* Array of const char * */
    apr_array_header_t *privgroups;     /* Array of const char * */
	apr_array_header_t *oper_attribs;	/* Array of const char * */
};

/* Used for passing things around */
typedef struct {
    request_rec *r; /* apache request struct */

    struct server_config *sconf;
    struct dir_config *dconf;

    apr_table_t **entries;  /* retrieved ldap entries */
    size_t numEntries;

    apr_table_t *envvars;    /* which attributes to place into environment */
    apr_table_t *privgroups; /* which privgroups to check and place into
                                environment */
    int legacymode;

    LDAP *ld;
    char **attrs;            /* attributes to retrieve from LDAP, (null = all)
							  * (+ = operational)
                              */
    char *filter;
    int port;

    const char *authrule;    /* what group or rule was the user authorized on
                              */

    apr_table_t *privgroup_cache;
                             /* cached privgroup comparison results; keys are
                                privgroup names; values should be "TRUE" or
                                "FALSE" */
} MWAL_LDAP_CTXT;

/* config.c */

/* Create a new server or directory configuration, used in the module hooks. */
void *mwl_dir_config_create(apr_pool_t *, char *path);
void *mwl_server_config_create(apr_pool_t *, server_rec *s);

/* Merge two server or directory configurations, used in the module hooks. */
void *mwl_dir_config_merge(apr_pool_t *, void *, void *);
void *mwl_server_config_merge(apr_pool_t *, void *, void *);

/* Perform final checks on the configuration (called from post_config hook). */
void mwl_config_init(server_rec *, struct server_config *, apr_pool_t *);

#endif
