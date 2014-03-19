/*
 * Message logging for an Apache module.
 *
 * These functions are used for message logging callbacks inside the WebAuth
 * context.  Following the capabilities of libwebauth, four levels of error
 * reporting are available: trace, info, notice, and warning.  More severe
 * errors are assumed to return an error from the WebAuth library and will
 * then be logged directly by the module.
 *
 * These functions all do per-request logging.  Logging without request
 * information must be done separately.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config-mod.h>
#include <portable/apache.h>
#include <portable/apr.h>

#include <modules/webkdc/mod_webkdc.h>
#include <webauth/basic.h>
#include <util/macros.h>

APLOG_USE_MODULE(webkdc);

/*
 * For Apache 2.2 and earlier, we want to add the module name as a prefix to
 * each of the messages, since there's no other way to determine where the
 * message came from.  In Apache 2.4, the module is part of the metadata, so
 * we should omit this.
 */
#if AP_SERVER_MAJORVERSION_NUMBER > 2           \
    || (AP_SERVER_MAJORVERSION_NUMBER == 2      \
        && AP_SERVER_MINORVERSION_NUMBER >= 4)
# define LOG_FUNC(name, level, module)                                  \
    void                                                                \
    name(struct webauth_context *ctx UNUSED, void *data,                \
         const char *msg)                                               \
    {                                                                   \
        request_rec *r = data;                                          \
        ap_log_rerror(APLOG_MARK, APLOG_ ## level, 0, r, "%s", msg);    \
    }
#else
# define LOG_FUNC(name, level, module)                          \
    void                                                        \
    name(struct webauth_context *ctx UNUSED, void *data,        \
         const char *message)                                   \
    {                                                           \
        request_rec *r = data;                                  \
        ap_log_rerror(APLOG_MARK, APLOG_ ## level, 0, r,        \
                      "mod_" #module ": %s", message);          \
    }
#endif

LOG_FUNC(mwk_log_trace,   TRACE1,  webkdc)
LOG_FUNC(mwk_log_info,    INFO,    webkdc)
LOG_FUNC(mwk_log_notice,  NOTICE,  webkdc)
LOG_FUNC(mwk_log_warning, WARNING, webkdc)
