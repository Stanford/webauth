#ifndef MOD_WEBAUTHLDAP_H
#define MOD_WEBAUTHLDAP_H

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"

#include "apr.h"
#include "apr_lib.h"
#include "apr_file_io.h"
#include "apr_file_info.h"
#include "apr_errno.h"
#include "apr_strings.h"
#include "apr_pools.h"
#include "apr_tables.h"
#include "apr_xml.h"
#include "apr_base64.h"


/* constants */
#define MAX_ENV_VALUES 128
#define LDAP_SIZELIMIT -1
#define PRIVGROUP_DIRECTIVE "privgroup"
#define DN_ATTRIBUTE "dn"

/* environment variables */
#define ENV_KRB5_TICKET "KRB5CCNAME"

/* defines for config directives */
#define CD_Base "WebAuthLdapBase"
#define CM_Base "Search base for LDAP lookup"

#define CD_Binddn "WebAuthLdapBindDN"
#define CM_Binddn "bind DN for the LDAP connection"

#define CD_Debug "WebAuthLdapDebug"
#define CM_Debug "Turn ldap module debugging on or off"
#define DF_Debug 0

#define CD_Filter_templ "WebAuthLdapFilter"
#define CM_Filter_templ "ldap search filter to use"
#define DF_Filter_templ "uid=USER"
#define FILTER_MATCH "USER"

#define CD_Privgroupattr "WebAuthLdapAuthorizationAttribute"
#define CM_Privgroupattr "ldap attribute to use for priviledge groups"

#define CD_Attribs "WebAuthLdapAttribute"
#define CM_Attribs "additional ldap attributes to place into the environment"

#define CD_Host "WebAuthLdapHost"
#define CM_Host "LDAP Host for LDAP lookup"

#define CD_Keytab "WebAuthLdapKeytab"
#define CM_Keytab "keytab and the principal to bind as"

#define CD_Tktcache "WebAuthLdapTktCache"
#define CM_Tktcache "K5 ticket cache for ldap"

#define CD_Port "WebAuthLdapPort"
#define CM_Port "ldap port to bind to"
#define DF_Port "0"

#define CD_SSL "WebAuthLdapSSL"
#define CM_SSL "use ssl or not"
#define DF_SSL 0

#define CD_Authrule "WebAuthLdapAuthrule"
#define CM_Authrule "display the rule used to authorize user"
#define DF_Authrule 0

enum {
    E_Attribs,
    E_Authrule,
    E_Base,
    E_Binddn,
    E_Debug,
    E_Filter_templ,
    E_Host,
    E_Keytab,
    E_Port,
    E_Privgroupattr,
    E_SSL,
    E_Tktcache

};

module webauthldap_module;

/* defaults struct passed to SASL */
typedef struct {
    char *mech;
    char *realm;
    char *authcid;
    char *passwd;
    char *authzid;
} MWAL_SASL_DEFAULTS;


/* server conf stuff */
typedef struct {

    char* base;
    char* binddn;           // not used with the Stanford openldap server
    int   debug;
    char* filter_templ;
    char* host;
    char* keytab;
    char* port;
    char* principal;
    char* privgroupattr;
    int   set_authrule;
    int   ssl;
    char* tktcache;
    int ldapversion;
    int scope;

} MWAL_SCONF;


/* directory conf stuff - looks like nothing so far*/
typedef struct {

    apr_array_header_t* attribs;

} MWAL_DCONF;


// Used for passing things around
typedef struct {
    request_rec * r; // apache request struct

    MWAL_SCONF* sconf;
    MWAL_DCONF* dconf;

    apr_table_t ** entries;  // retrieved ldap entries 
    int numEntries;

    apr_table_t* envvars;    // which attributes to place into environment
    int legacymode;

    LDAP *ld;
    char **attrs;            // attributes to retrieve from LDAP, (null = all)
    char*  filter;
    int    port;

    char*  authrule; 	     // what group or rule was the user authorized on

} MWAL_LDAP_CTXT;


#endif


/* 
** Local variables: 
** mode: c 
** c-basic-offset: 4 
** indent-tabs-mode: nil 
** end: 
*/
