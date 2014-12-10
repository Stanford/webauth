/*
 * Test WebKDC login support with multifactor.
 *
 * WebKDC login tests that use either multifactor or the user information
 * service.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <time.h>

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/remctl.h>
#include <tests/tap/webauth.h>
#include <webauth/basic.h>
#include <webauth/keys.h>
#include <webauth/webkdc.h>

/* Tests to run with the default userinfo configuration. */
static const struct wat_login_test tests_default[] = {

    /* Test basic authentication with a user information service. */
    {
        "Basic authentication",
        LOGIN_SUCCESS,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "x,x1", 3, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "x,x1", 1, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            { "mini", NULL, "webkdc", NULL, 0, "x,x1", "c", 1, 0, 0 },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /* The same, but attempt to access a restricted URL. */
    {
        "Authentication to restricted URL",
        WA_PEC_AUTH_REJECTED,
        "authentication rejected (rejected by user information service)",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "x,x1", 3, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0,
                "https://example.com/restrict/", NULL, NULL, NULL, 0, NULL, 0
            }
        },
        {
            "<strong>You are restricted!</strong>  &lt;_&lt;;", NULL,
            NO_FACTOR_DATA,
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "x,x1", 3, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Request an X.509 factor even though the user doesn't have that listed
     * as a supported factor.  Since they have a webkdc-proxy token with that
     * factor, this should work.
     */
    {
        "Authentication requiring an X.509 factor",
        LOGIN_SUCCESS,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "x,x1", 3, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "x", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "x,x1", 1, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            { "mini", NULL, "webkdc", NULL, 0, "x,x1", "c", 1, 0, 0 },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /* Request a level of assurance that cannot be satisfied. */
    {
        "Authentication requiring a too-high LoA",
        WA_PEC_LOA_UNAVAILABLE,
        "insufficient level of assurance",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "x,x1", 3, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "x", NULL, 4, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "x,x1", 1, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Request a session password factor.  This should fail with a forced
     * login message since we only have cookie factors for the session.
     *
     * This and the next two tests are also run in the basic webkdc-login test
     * suite, but we want to run them again here with a user information
     * service configured to ensure that behavior doesn't change with a real
     * user information service instead of the implicit "p" factor.
     */
    {
        "Authentication requiring a p session factor, old proxy",
        WA_PEC_LOGIN_FORCED,
        "forced authentication, must reauthenticate",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "x,x1", 3, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, "p", 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "p", "p",
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "x,x1", 1, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * The same, setting the webkdc-proxy creation to now.  This still doesn't
     * work, but for a different reason: the webkdc-proxy token doesn't have a
     * password factor.
     */
    {
        "Authentication requiring a p session factor, current proxy",
        WA_PEC_LOGIN_FORCED,
        "forced authentication, must reauthenticate",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "x,x1", 3, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, "p", 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "p", "p",
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "x,x1", 1, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /* Instead, request an X.509 session factor.  This should work. */
    {
        "Authentication requiring an x session factor",
        LOGIN_SUCCESS,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "x,x1", 3, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, "x", 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "x,x1", 1, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            { "mini", NULL, "webkdc", NULL, 0, "x,x1", "x,x1", 1, 0, 0 },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Request an OTP factor that isn't configured for this user.  This should
     * be rejected with multifactor unavailable.
     */
    {
        "Require an unavailable factor",
        WA_PEC_MULTIFACTOR_UNAVAILABLE,
        "multifactor required but not configured",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "p", 3, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "o", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "o", "p",
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "p", 1, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * The same, while requesting a Kerberos authenticator.  The error message
     * should not change, since unavailable multifactor is stronger.
     */
    {
        "Require an unavailable factor and a Kerberos authenticator",
        WA_PEC_MULTIFACTOR_UNAVAILABLE,
        "multifactor required but not configured",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "p", 3, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "krb5", NULL, NULL, 0, "https://example.com/", NULL,
                "o", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "o", "p",
            {
                {
                    "mini", "remuser", "WEBKDC:remuser", "mini", 4,
                    "p", 1, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Try with the factor user, which should require multifactor since we
     * haven't included a d factor in our initial authentication factors.
     */
    {
        "User information service requires factor from arg",
        WA_PEC_MULTIFACTOR_REQUIRED,
        "multifactor login required",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "factor", "remuser", "WEBKDC:remuser", "factor", 6,
                    "p", 3, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "m", "p,m,o,o2",
            {
                {
                    "factor", "remuser", "WEBKDC:remuser", "factor", 6,
                    "p", 1, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * The same, but requesting a Kerberos authenticator.  The error message
     * indicating that a proxy token is required should override the
     * multifactor required error.
     */
    {
        "Kerberos authenticator and multifactor required",
        WA_PEC_PROXY_TOKEN_REQUIRED,
        "webkdc-proxy token required",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "factor", "remuser", "WEBKDC:remuser", "factor", 6,
                    "p", 3, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "krb5", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "m", "p,m,o,o2",
            {
                {
                    "factor", "remuser", "WEBKDC:remuser", "factor", 6,
                    "p", 1, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /* The same, but requesting a Kerberos proxy token. */
    {
        "Kerberos proxy token and multifactor required",
        WA_PEC_PROXY_TOKEN_REQUIRED,
        "webkdc-proxy token required",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "factor", "remuser", "WEBKDC:remuser", "factor", 6,
                    "p", 3, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "proxy", NULL, "krb5", NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "m", "p,m,o,o2",
            {
                {
                    "factor", "remuser", "WEBKDC:remuser", "factor", 6,
                    "p", 1, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Add a d factor to the webkdc-proxy token and try again.  This should
     * then work.
     */
    {
        "Provide factor required by userinfo in arg",
        LOGIN_SUCCESS,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "factor", "remuser", "WEBKDC:remuser", "factor", 6,
                    "p,d", 3, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "factor", "remuser", "WEBKDC:remuser", "factor", 6,
                    "p,d", 1, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            { "factor", NULL, "webkdc", NULL, 0, "p,d", "p,d", 1, 0, 0 },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Now try authenticating a user who has multifactor configured, again
     * with a request of multifactor.  This will produce a different error
     * message.
     */
    {
        "Require an available factor",
        WA_PEC_MULTIFACTOR_REQUIRED,
        "multifactor login required",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "full", "remuser", "WEBKDC:remuser", "full", 4,
                    "p", 3, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "o", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "o,m,o3", "p,m,o,o3",
            {
                {
                    "full", "remuser", "WEBKDC:remuser", "full", 4,
                    "p", 3, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            1310675733,
            NO_AUTHZ_IDS
        }
    },

    /* Add a second webkdc-proxy token representing an OTP login. */
    {
        "Successful authentication with two proxy tokens",
        LOGIN_SUCCESS,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "full", "remuser", "WEBKDC:remuser", "full", 4,
                    "p", 3, 10 * 60, 60 * 60, "c"
                },
                {
                    "full", "remuser", "WEBKDC:remuser", "full", 4,
                    "o,o3", 2, 2 * 60, 30 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "o", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "full", "remuser", "WEBKDC:remuser", "full", 4,
                    "o,o3,p,m", 3, 10 * 60, 30 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            {
                "full", NULL, "webkdc", NULL, 0, "o,o3,p,m", "o,o3,c", 3,
                0, 30 * 60
            },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            1310675733,
            NO_AUTHZ_IDS
        }
    },

    /* Attempt OTP with an incorrect code. */
    {
        "Incorrect OTP authentication",
        WA_PEC_LOGIN_REJECTED,
        "user may not authenticate (rejected by validation service)",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            {
                { "full", NULL, "654321", NULL, "DEVICEID", 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "o", NULL, 0, NULL, 0
            }
        },
        {
            "<em>OTP3</em> down.  &lt;_&lt;;", "RESET_PIN",
            NO_FACTOR_DATA,
            NO_TOKENS_WKPROXY,
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Switch to the correct OTP code and add back a webkdc-proxy token
     * representing an earlier password authentication.  This combination is
     * the typical case for a multifactor login and should result in
     * satisfying the requirement for multifactor.
     *
     * We should get the full suite of session factors here, since the proxy
     * token is fresh.
     */
    {
        "Successful authentication with OTP login and proxy",
        LOGIN_SUCCESS,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            {
                { "full", NULL, "123456", NULL, "DEVICEID", 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "full", "remuser", "WEBKDC:remuser", "full", 4,
                    "p", 3, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "m", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "full", "otp", "WEBKDC:otp", "full", 4,
                    "o,o3,p,m,d,u", 3, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            { "full", "d,u", 0, 1893484802 },
            {
                "full", NULL, "webkdc", NULL, 0, "o,o3,p,m,d,u",
                "o,o3,p,m,d,u", 3, 0, 60 * 60
            },
            EMPTY_TOKEN_PROXY,
            {
                { "127.0.0.2", "example.com", 1335373919 },
                { "127.0.0.3", "www.example.com", 0 },
                { NULL, NULL, 0 },
            },
            1310675733,
            NO_AUTHZ_IDS
        }
    },

    /* Same authentication, but add an input webkdc-factor token. */
    {
        "Successful authentication with OTP login, proxy, and factor",
        LOGIN_SUCCESS,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            {
                { "full", NULL, "123456", NULL, "DEVICEID", 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "full", "remuser", "WEBKDC:remuser", "full", 4,
                    "p", 3, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            {
                { "full", "k", 10 * 60, 60 * 60 },
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR
            },
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "m", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "full", "otp", "WEBKDC:otp", "full", 4,
                    "o,o3,p,m,k,d,u", 3, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            { "full", "d,u,k", 10 * 60, 60 * 60 },
            {
                "full", NULL, "webkdc", NULL, 0, "o,o3,p,m,k,d,u",
                "o,o3,p,m,k,d,u", 3, 0, 60 * 60
            },
            EMPTY_TOKEN_PROXY,
            {
                { "127.0.0.2", "example.com", 1335373919 },
                { "127.0.0.3", "www.example.com", 0 },
                { NULL, NULL, 0 },
            },
            1310675733,
            NO_AUTHZ_IDS
        }
    },

    /*
     * If the webkdc-factor token is older than the invalid-before cutoff,
     * we will ignore it and not add the additional factor, including the new
     * webkdc-factor information that we get from OTP.
     */
    {
        "Old webkdc-factor token",
        LOGIN_SUCCESS,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            {
                { "full", NULL, "123456", NULL, "DEVICEID", 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "full", "remuser", "WEBKDC:remuser", "full", 4,
                    "p", 3, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            {
                { "full", "k", 1365630518, 60 * 60 },
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR
            },
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "m", "m", 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "full", "otp", "WEBKDC:otp", "full", 4,
                    "o,o3,p,m,d,u", 3, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            { "full", "d,u", 0, 1893484802 },
            {
                "full", NULL, "webkdc", NULL, 0, "o,o3,p,m,d,u",
                "o,o3,p,m,d,u", 3, 0, 60 * 60
            },
            EMPTY_TOKEN_PROXY,
            {
                { "127.0.0.2", "example.com", 1335373919 },
                { "127.0.0.3", "www.example.com", 0 },
                { NULL, NULL, 0 },
            },
            1310675733,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Go back to just the webkdc-proxy and OTP login tokens and request
     * multifactor session factors as well.  This won't work because the
     * password webkdc-proxy token is too old and hence can't contribute to
     * the session factors, even though we're logging in.
     */
    {
        "Session multifactor with old proxy",
        WA_PEC_LOGIN_FORCED,
        "forced authentication, must reauthenticate",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            {
                { "full", NULL, "123456", NULL, "DEVICEID", 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "full", "remuser", "WEBKDC:remuser", "full", 4,
                    "p", 3, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "m", "m", 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "m", "p,m,o,o3",
            {
                {
                    "full", "otp", "WEBKDC:otp", "full", 4,
                    "o,o3,p,m,d,u", 3, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            { "full", "d,u", 0, 1893484802 },
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            {
                { "127.0.0.2", "example.com", 1335373919 },
                { "127.0.0.3", "www.example.com", 0 },
                { NULL, NULL, 0 },
            },
            1310675733,
            NO_AUTHZ_IDS
        }
    },

    /* But if the webkdc-proxy token is current, this does work. */
    {
        "Session multifactor with current proxy",
        LOGIN_SUCCESS,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            {
                { "full", NULL, "123456", NULL, "DEVICEID", 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "full", "remuser", "WEBKDC:remuser", "full", 4,
                    "p", 3, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "m", "m", 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "full", "otp", "WEBKDC:otp", "full", 4,
                    "o,o3,p,m,d,u", 3, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            { "full", "d,u", 0, 1893484802 },
            {
                "full", NULL, "webkdc", NULL, 0, "o,o3,p,m,d,u",
                "o,o3,p,m,d,u", 3, 0, 60 * 60
            },
            EMPTY_TOKEN_PROXY,
            {
                { "127.0.0.2", "example.com", 1335373919 },
                { "127.0.0.3", "www.example.com", 0 },
                { NULL, NULL, 0 },
            },
            1310675733,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Test the error message returned when a session factor is required and
     * the user has just completed a password authentication.  We want to be
     * sure we return the error to force multifactor authentication, not
     * forced login, since the latter would create a loop.  (This bug was
     * present in WebAuth 3.5.3.)
     */
    {
        "Session multifactor, password login",
        WA_PEC_MULTIFACTOR_REQUIRED,
        "multifactor login required",
        {
            { "<krb5-principal>", 0, 0 },
            {
                { "<userprinc>", "<password>", NULL, NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, "o", 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "o", "h,m,p,o",
            {
                {
                    "<userprinc>", "krb5", "<webkdc-principal>", NULL, 0,
                    "p,h,m", 0, 0, 0, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    },

    /*
     * Try requesting only a level of assurance, with a webkdc-proxy token for
     * an insufficient level of assurance, but a level of assurance that the
     * user can meet.  Ensure the correct error message is returned.  Use
     * normal instead of full as the user so that multifactor isn't forced.
     */
    {
        "Meetable but unmet LoA requirement",
        WA_PEC_MULTIFACTOR_REQUIRED,
        "multifactor login required",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "normal", "remuser", "WEBKDC:remuser", "normal", 6,
                    "p", 2, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 3, NULL, 0
            }
        },
        {
            NULL, NULL,
            NULL, "p,m,o,o2",
            {
                {
                    "normal", "remuser", "WEBKDC:remuser", "normal", 6,
                    "p", 2, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            1310675733,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Request multifactor, provide a webkdc-proxy token indicating a password
     * authentication, and authenticate as the user who gets additional
     * factors.  The additional factors should not be added because we didn't
     * just authenticate.
     */
    {
        "Additional factors not added for proxy authentication",
        WA_PEC_MULTIFACTOR_REQUIRED,
        "multifactor login required",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "<userprinc>", "remuser", "WEBKDC:remuser", "full", 4,
                    "p", 3, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "m", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "m", "h,m,p,o",
            {
                {
                    "<userprinc>", "remuser", "WEBKDC:remuser", "full", 4,
                    "p", 0, 0, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Now, switch to providing a login token instead.  This will allow us to
     * merge the additional factors.
     */
    {
        "Factors added for login authentication",
        LOGIN_SUCCESS,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            {
                { "<userprinc>", "<password>", NULL, NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "m", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "<userprinc>", "krb5", "<webkdc-principal>", NULL, 0,
                    "p,h,m", 0, 0, 0, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            {
                "<userprinc>", NULL, "webkdc", NULL, 0, "p,h,m", "p,h,m",
                0, 0, 0
            },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Request random multifactor for a user who will get lucky and not need
     * to authenticate with multifactor.
     */
    {
        "Random multifactor for lucky user",
        LOGIN_SUCCESS,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "normal", "remuser", "WEBKDC:remuser", "normal", 6,
                    "p", 1, 0, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "rm", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "normal", "remuser", "WEBKDC:remuser", "normal", 6,
                    "p,rm", 1, 0, 0, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            {
                "normal", NULL, "webkdc", NULL, 0, "p,rm", "p,rm",
                1, 0, 60 * 60
            },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            1310675733,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Change the proxy token to indicate that random multifactor has already
     * been checked for, and then try someone who would not get lucky and
     * confirm that they're still allowed in.  Also make the proxy token older
     * so that it doesn't contribute to session factors.
     */
    {
        "Existing random multifactor",
        LOGIN_SUCCESS,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "random", "remuser", "WEBKDC:remuser", "random", 6,
                    "p,rm", 1, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "rm", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "random", "remuser", "WEBKDC:remuser", "random", 6,
                    "p,rm", 1, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            {
                "random", NULL, "webkdc", NULL, 0, "p,rm", "c",
                1, 0, 60 * 60
            },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Require random multifactor for the session, which should force a check
     * even though the webkdc-proxy token indicates a check was already done
     * since the webkdc-proxy token is too old to provide session factors.
     * This should fail and indicate multifactor is required.
     */
    {
        "Unlucky random multifactor for session",
        WA_PEC_MULTIFACTOR_REQUIRED,
        "multifactor login required",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "random", "remuser", "WEBKDC:remuser", "random", 6,
                    "p,rm", 1, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "rm", "rm", 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "m,rm", "p,m,o,o2",
            {
                {
                    "random", "remuser", "WEBKDC:remuser", "random", 6,
                    "p,rm", 1, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * Similarly, requiring random multifactor for the initial factors should
     * fail if the webkdc-proxy token doesn't already have random multifactor
     * and we have an unlucky user.
     */
    {
        "Unlucky random multifactor for initial",
        WA_PEC_MULTIFACTOR_REQUIRED,
        "multifactor login required",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "random", "remuser", "WEBKDC:remuser", "random", 6,
                    "p", 1, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "rm", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "rm,m", "p,m,o,o2",
            {
                {
                    "random", "remuser", "WEBKDC:remuser", "random", 6,
                    "p", 1, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * But if we have a regular multifactor webkdc-proxy token, that allows
     * random multifactor as well.  The factors for the id and webkdc-proxy
     * tokens should just include multifactor.
     */
    {
        "Multifactor satisfies random",
        LOGIN_SUCCESS,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "random", "remuser", "WEBKDC:remuser", "random", 6,
                    "p,o,o3,m", 1, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "rm", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "random", "remuser", "WEBKDC:remuser", "random", 6,
                    "p,o,o3,m", 1, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            {
                "random", NULL, "webkdc", NULL, 0, "p,o,o3,m", "c",
                1, 0, 60 * 60
            },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /* Try that with session multifactor, which should fail. */
    {
        "Initial multifactor does not satisfy random session",
        WA_PEC_LOGIN_FORCED,
        "forced authentication, must reauthenticate",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "random", "remuser", "WEBKDC:remuser", "random", 6,
                    "p,o,o3,m", 1, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "rm", "rm", 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "rm", "p,m,o,o2",
            {
                {
                    "random", "remuser", "WEBKDC:remuser", "random", 6,
                    "p,o,o3,m,rm", 1, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    }
};

/* Tests that should be run with a timeout configured. */
static const struct wat_login_test tests_timeout[] = {

    /*
     * Switch users to one for which the user information service won't return
     * in time.  Now, authentication should fail since we can't contact the
     * user information service.
     */
    {
        "User information service timeout",
        WA_PEC_SERVER_FAILURE,
        "internal server failure",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "delay", "remuser", "WEBKDC:remuser", "delay", 5,
                    "p", 1, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "rm", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "delay", "remuser", "WEBKDC:remuser", "delay", 5,
                    "p", 1, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },
};


/* Tests that should be run with a timeout and ignore errors. */
static const struct wat_login_test tests_ignore_failure[] = {

    /*
     * If we say to ignore user information errors, random multifactor should
     * succeed based on the existing proxy information that we have.
     */
    {
        "Random multifactor with multifactor and timeout",
        LOGIN_SUCCESS,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "delay", "remuser", "WEBKDC:remuser", "delay", 5,
                    "p,o,o3,m", 1, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "rm", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "delay", "remuser", "WEBKDC:remuser", "delay", 5,
                    "p,o,o3,m", 0, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            {
                "delay", NULL, "webkdc", NULL, 0, "p,o,o3,m", "c",
                0, 0, 60 * 60
            },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    },

    /*
     * But if we remove multifactor from the proxy token, random multifactor
     * should now fail, since we were unable to contact the user information
     * service.
     */
    {
        "Random multifactor without multifactor and timeout",
        WA_PEC_MULTIFACTOR_UNAVAILABLE,
        "multifactor required but not configured",
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "delay", "remuser", "WEBKDC:remuser", "delay", 5,
                    "p", 1, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                "rm", NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            "rm", "p",
            {
                {
                    "delay", "remuser", "WEBKDC:remuser", "delay", 5,
                    "p", 0, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        }
    }
};


int
main(void)
{
    apr_pool_t *pool = NULL;
    apr_array_header_t *local_realms, *permitted_realms;
    struct kerberos_config *krbconf;
    struct webauth_context *ctx;
    struct webauth_keyring *ring;
    struct webauth_user_config user_config;
    struct webauth_webkdc_config config;
    char *keyring;
    int s;
    size_t i;

    /* Skip this test if built without remctl support. */
#ifndef HAVE_REMCTL
    skip_all("built without remctl support");
#endif

    /* Load the Kerberos configuration. */
    krbconf = kerberos_setup(TAP_KRB_NEEDS_BOTH);

    /* Use lazy planning so that test counts can vary on some errors. */
    plan_lazy();

    /* Initialize APR and WebAuth. */
    if (apr_initialize() != APR_SUCCESS)
        bail("cannot initialize APR");
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS)
        bail("cannot create memory pool");
    if (webauth_context_init_apr(&ctx, pool) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Load the precreated keyring that we'll use for token encryption. */
    keyring = test_file_path("data/keyring");
    s = webauth_keyring_read(ctx, keyring, &ring);
    if (s != WA_ERR_NONE)
        bail("cannot read %s: %s", keyring, webauth_error_message(ctx, s));
    test_file_path_free(keyring);

    /* Start remctld. */
    remctld_start(krbconf, "data/conf-webkdc", (char *) 0);

    /* Provide basic configuration to the WebKDC code. */
    local_realms     = apr_array_make(pool, 1, sizeof(const char *));
    permitted_realms = apr_array_make(pool, 1, sizeof(const char *));
    APR_ARRAY_PUSH(local_realms, const char *) = "none";
    memset(&config, 0, sizeof(config));
    config.local_realms     = local_realms;
    config.permitted_realms = permitted_realms;
    config.keytab_path      = krbconf->keytab;
    config.principal        = krbconf->principal;
    config.login_time_limit = 5 * 60;
    s = webauth_webkdc_config(ctx, &config);
    is_int(WA_ERR_NONE, s, "WebKDC configuration succeeded");

    /* Add configuration for the user information service. */
    memset(&user_config, 0, sizeof(user_config));
    user_config.protocol  = WA_PROTOCOL_REMCTL;
    user_config.host      = "localhost";
    user_config.port      = 14373;
    user_config.identity  = config.principal;
    user_config.command   = "test";
    user_config.keytab    = config.keytab_path;
    user_config.principal = config.principal;
    s = webauth_user_config(ctx, &user_config);
    is_int(WA_ERR_NONE, s, "User information config accepted");

    /* Run the basic set of tests. */
    for (i = 0; i < ARRAY_SIZE(tests_default); i++)
        run_login_test(ctx, &tests_default[i], ring, krbconf);

    /* Add a timeout to the user information service queries. */
    user_config.timeout = 1;
    s = webauth_user_config(ctx, &user_config);
    is_int(WA_ERR_NONE, s, "Setting user information timeout succeeds");

    /* Run the tests requiring a timeout. */
    for (i = 0; i < ARRAY_SIZE(tests_timeout); i++)
        run_login_test(ctx, &tests_timeout[i], ring, krbconf);

    /* Configure the user information service to ignore errors. */
    user_config.ignore_failure = true;
    s = webauth_user_config(ctx, &user_config);
    is_int(WA_ERR_NONE, s, "Setting user information ignore succeeds");

    /* Run the tests requiring a timeout and ignore failure. */
    for (i = 0; i < ARRAY_SIZE(tests_ignore_failure); i++)
        run_login_test(ctx, &tests_ignore_failure[i], ring, krbconf);

    /*
     * Re-run the basic tests with JSON.  Don't bother with the timeout and
     * ignore error tests, since that functionality with JSON is tested by the
     * userinfo test suite directly.
     */
#ifdef HAVE_JANSSON
    user_config.timeout = 0;
    user_config.ignore_failure = false;
    user_config.command = "test-json";
    user_config.json = true;
    s = webauth_user_config(ctx, &user_config);
    is_int(WA_ERR_NONE, s, "Setting user information protocol to JSON");
    for (i = 0; i < ARRAY_SIZE(tests_default); i++)
        run_login_test(ctx, &tests_default[i], ring, krbconf);
#else
    skip("not built with JSON support");
#endif

    /* Clean up. */
    apr_terminate();
    return 0;
}
