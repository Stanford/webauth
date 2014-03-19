/*
 * Portability wrapper around Apache headers.
 *
 * This header includes the following Apache headers:
 *
 *     #include <httpd_h>
 *     #include <http_config.h>
 *     #include <http_core.h>
 *     #include <http_log.h>
 *     #include <http_protocol.h>
 *     #include <http_request.h>
 *     #include <unixd.h>
 *
 * and then attempts to adjust for older versions of Apache 2.x.  One will
 * generally want to include config-mod.h instead of config.h before this
 * header, since config.h normally defines PACKAGE_* symbols that will
 * conflict with Apache's defines.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 *
 * The authors hereby relinquish any claim to any copyright that they may have
 * in this work, whether granted under contract or by operation of law or
 * international treaty, and hereby commit to the public, at large, that they
 * shall not, at any time in the future, seek to enforce any copyright in this
 * work against any person or entity, or prevent any person or entity from
 * copying, publishing, distributing or creating derivative works of this
 * work.
 */

#ifndef PORTABLE_APACHE_H
#define PORTABLE_APACHE_H 1

/*
 * Allow inclusion of config.h to be skipped, since sometimes we have to use a
 * stripped-down version of config.h with a different name.
 */
#ifndef CONFIG_H_INCLUDED
# include <config.h>
#endif

/*
 * Automake always defines this, which causes Heimdal to pull in its config.h
 * and leak Autoconf definitions into the package namespace, which in turn
 * conflicts with Apache's own definitions.  Undefine it to work around that
 * problem.
 *
 * Arguably, this should be in portable/krb5.h, since the problem is actually
 * in the Heimdal headers, but it only poses problems when using the Apache
 * includes, which also leak the package defines.
 */
#undef HAVE_CONFIG_H

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <unixd.h>

/* Apache 2.0 did not have ap_get_server_description. */
#if !HAVE_DECL_AP_GET_SERVER_DESCRIPTION
# define ap_get_server_description() ap_get_server_version()
#endif

/* Apache 2.2 renamed the incorrect ap_http_method to ap_http_scheme. */
#ifndef ap_http_scheme
# define ap_http_scheme(r) ap_http_method(r)
#endif

/*
 * Apache 2.2 and earlier used check_user_id instead of check_authn, which
 * doesn't take the final flag saying whether to do checks per URI.
 */
#if !HAVE_DECL_AP_HOOK_CHECK_AUTHN
# define ap_hook_check_authn(f, b, a, o, t) \
    ap_hook_check_user_id((f), (b), (a), (o))
#endif

/* The useragent_ip request member is new in Apache 2.4. */
#if !HAVE_REQUEST_REC_USERAGENT_IP
# define useragent_ip connection->remote_ip
#endif

/* Apache 2.4 renamed this to stay in the ap_* namespace. */
#if !HAVE_DECL_AP_UNIXD_CONFIG
# define ap_unixd_config unixd_config
#endif

/*
 * This macro was added in Apache 2.4.  It declares both the per-module
 * logging data and the module data struct.  In earlier versions, declare the
 * data struct so that we can rely on it being declared for other purposes.
 */
#ifndef APLOG_USE_MODULE
# define APLOG_USE_MODULE(foo) \
    extern module AP_MODULE_DECLARE_DATA foo##_module;
#endif

/*
 * Apache 2.4 introduced granular levels of trace logging.  For older
 * versions, collapse them all into APLOG_DEBUG.
 */
#ifndef APLOG_TRACE1
# define APLOG_TRACE1 APLOG_DEBUG
# define APLOG_TRACE2 APLOG_DEBUG
# define APLOG_TRACE3 APLOG_DEBUG
# define APLOG_TRACE4 APLOG_DEBUG
# define APLOG_TRACE5 APLOG_DEBUG
# define APLOG_TRACE6 APLOG_DEBUG
# define APLOG_TRACE7 APLOG_DEBUG
# define APLOG_TRACE8 APLOG_DEBUG
#endif

#endif /* !PORTABLE_APACHE_H */
