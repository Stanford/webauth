# WebLogin interactions with the browser for WebAuth
#
# Written by Roland Schemers <schemers@stanford.edu>
# Extensive updates by Russ Allbery <eagle@eyrie.org>
# Rewritten for CGI::Application by Jon Robertson <jonrober@stanford.edu>
# Copyright 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012,
#     2013, 2014 The Board of Trustees of the Leland Stanford Junior University
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

##############################################################################
# Modules and declarations
##############################################################################

package WebLogin;
use base qw (CGI::Application);
use CGI::Application::Plugin::AutoRunmode;
use CGI::Application::Plugin::Forward;
use CGI::Application::Plugin::Redirect;
use CGI::Application::Plugin::TT;

require 5.006;

use strict;
use warnings;

use CGI::Cookie ();
use FreezeThaw qw(freeze thaw);
use MIME::Base64 qw(encode_base64 decode_base64);
use POSIX qw(strftime);
use Template ();
use Time::Duration;
use URI ();
use URI::QueryParam ();
use WebAuth 3.06 qw(:const);
use WebKDC 2.06;
use WebKDC::Config 1.00;
use WebKDC::WebKDCException 1.05;

# Required only if we're going to do replay caching or rate limiting.
if (@WebKDC::Config::MEMCACHED_SERVERS) {
    require Cache::Memcached;
    require Digest::SHA;
}

# Required if we're going to send remctl commands for multifactor.
if ($WebKDC::Config::MULTIFACTOR_SERVER) {
    require Net::Remctl;
}

our $VERSION;

# This version matches the version of WebAuth with which this module was
# released, but with two digits for the minor and patch versions.
BEGIN {
    $VERSION = '4.0700';
}

# The CGI::Application parameters that must be cleared for each query.
our @PER_QUERY_PARAMS = qw(
    CPT is_error forced_login pretty_uri remuser_failed remuser_url
    script_name wpt_cookie
);

##############################################################################
# Configuration defaults
##############################################################################

# Set to true in order to enable debugging output.  This will be very chatty
# in the logs and may log security-sensitive tokens and other information.
our $DEBUG = 0;

# Set to true to log interesting error messages to stderr.
our $LOGGING = 1;

# The name of the cookie we set to ensure that the browser can handle cookies.
our $TEST_COOKIE = "WebloginTestCookie";

# The name of the cookie holding REMOTE_USER configuration information.
our $REMUSER_COOKIE = 'weblogin_remuser';

# Set any cookies we expire to this value, just in case a buggy browser
# refuses to actually delete the expired cookie.
our $EXPIRED_COOKIE = 'expired';

# The lifetime of the REMOTE_USER configuration cookie.
our $REMUSER_LIFETIME = '+365d';

# The lifetime of the kadmin/changepw token.
our $CHANGEPW_EXPIRES = 5 * 60;

# If the WebKDC is localhost, disable LWP certificate verification.  The
# WebKDC will have a certificate matching its public name, which will
# never match localhost, and we should be able to trust the server when
# connecting directly to localhost.
if ($WebKDC::Config::URL =~ m,^https://localhost/,) {
    $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;
}

#############################################################################
# CGI::Application setup functions
#############################################################################

# Set up initial application configuration.
sub setup {
    my ($self) = @_;

    # Configure the template.
    $self->tt_config(
                     TEMPLATE_OPTIONS => {
                         STAT_TTL     => 60,
                         COMPILE_DIR  =>
                             $WebKDC::Config::TEMPLATE_COMPILE_PATH,
                         COMPILE_EXT  => '.ttc',
                         INCLUDE_PATH => $WebKDC::Config::TEMPLATE_PATH,
                         EVAL_PERL    => 1,
                     },
                    );

    # Testing and logging - optional.  These can be set from the calling
    # script via:
    #    my $app = WebLogin->new(PARAMS => { logging => 1, debug => 1 });
    if (!defined $self->param ('logging')) {
        $self->param ('logging', $LOGGING);
    }
    if (!defined $self->param ('debug')) {
        $self->param ('debug', $DEBUG);
    }

    # Cookie values - optional.  See the logging comment above for how to set
    # from calling script.
    if (!defined $self->param ('remuser_cookie')) {
        $self->param ('remuser_cookie', $REMUSER_COOKIE);
    }
    if (!defined $self->param ('remuser_lifetime')) {
        $self->param ('remuser_lifetime', $REMUSER_LIFETIME);
    }
    if (!defined $self->param ('test_cookie')) {
        $self->param ('test_cookie', $TEST_COOKIE);
    }

    # If rate limiting or replay caching is enabled, connect to the memcached
    # server.
    if (@WebKDC::Config::MEMCACHED_SERVERS) {
        $self->{memcache} = Cache::Memcached->new ({
            servers => [ @WebKDC::Config::MEMCACHED_SERVERS ]
        });
    }
}

# Hook called before processing of each query.
sub cgiapp_prerun {
    my ($self) = @_;

    # Reset the header type and all header properties for clean state for
    # each request.
    $self->header_props ({});
    $self->header_type ('header');

    # Clear any per-query state that was stored as parameters.
    for my $param (@PER_QUERY_PARAMS) {
        $self->param ($param, undef);
    }

    # Clear all template parameters.
    $self->param ('template_params', {});
    $self->tt_clear_params;

    # The WebAuth object is per-query to do APR garbage collection.
    $self->{webauth} = WebAuth->new;

    # Set up the main request and response.
    $self->{request} = WebKDC::WebRequest->new;
    $self->{response} = WebKDC::WebResponse->new;

    # If we got our parameters via REDIRECT_QUERY_STRING, we're an error
    # handler and don't want to redirect later.
    $self->param ('is_error', defined $ENV{REDIRECT_QUERY_STRING});

    # Store the CPT if one was already generated, so that we have one place to
    # check.
    $self->param ('CPT', scalar $self->query->param ('CPT'));

    # Work around a bug in CGI that doesn't always set the script name.
    $self->query->{'.script_name'} = $ENV{SCRIPT_NAME};

    # Stash the script name as a parameter so that it can be easily updated
    # when we switch between password and login scripts.
    $self->param ('script_name', $self->query->script_name);
    print STDERR "Script name is ", $self->query->script_name, "\n"
        if $self->param ('debug');
}

##############################################################################
# Utility functions
##############################################################################

# Escape special characters in the principal name to match the escaping done
# by krb5_unparse_name.  This hopefully will make the principal suitable for
# passing to krb5_parse_name and getting the same results as the original
# unescaped principal.
sub krb5_escape {
    my ($self, $principal) = @_;
    $principal =~ s/\\/\\\\/g;
    $principal =~ s/\@/\\@/g;
    $principal =~ s/\t/\\t/g;
    $principal =~ s/\x08/\\b/g;
    $principal =~ s/\x00/\\0/g;
    return $principal;
}

# Encode a token for URL usage.
sub fix_token {
    my ($self, $token) = @_;
    $token =~ tr/ /+/;
    return $token;
}

# Check to see if the user has requested to remember their login device
# factor token.  To accomodate a form listing a checkbox for either yes or no
# depending on site preferences, we check to see if there is a settting, and
# if not, return the default.
#
# If the request method is GET, not POST, we're dealing with a single sign-on
# authentication, and we should always remember the login.
sub remember_login {
    my ($self) = @_;
    my $method = $self->query->request_method || 'POST';
    if ($method eq 'GET') {
        return 'yes';
    }
    if ($self->query->param ('remember_login')) {
        return $self->query->param ('remember_login');
    } else {
        return $WebKDC::Config::REMEMBER_FALLBACK;
    }
}

# Create and return a cookie that will expire an existing cookie.  Used in
# more than one place, so pulled out for logic.
sub expire_cookie {
    my ($self, $name, $secure) = @_;

    my $query = $self->query;
    my $cookie = $query->cookie (-name    => $name,
                                 -value   => $EXPIRED_COOKIE,
                                 -secure  => $secure,
                                 -expires => '-1d');
    return $cookie;
}

# Determine if we should clear a factor token.  We do this if the WebKDC sent
# some cookies but did not include a webkdc-factor token.  If it sent a
# webkdc-factor token, that will replace our current one, and if it sent no
# cookies at all, that may just be an initial login and we shouldn't clear any
# cookies.
sub should_clear_factor {
    my ($self) = @_;
    my $cookies = $self->{response}->cookies;
    if ($cookies && %{$cookies} && !exists $cookies->{webauth_wft}) {
        return 1;
    } else {
        return 0;
    }
}

# If there's a function pointer set in LOGIN_STATE_UNSERIALIZE, use that
# to parse and return the value of $login_state, else return the raw value.
sub parse_login_state {
    my ($self, $login_state) = @_;

    $login_state = decode_base64($login_state);
    if ( ref($WebKDC::Config::LOGIN_STATE_UNSERIALIZE) eq "CODE" ) {
        my $decoder = $WebKDC::Config::LOGIN_STATE_UNSERIALIZE;
        $login_state = &{$decoder}($login_state);
    }
    return $login_state;
}

##############################################################################
# Output related functions
##############################################################################

# Wrapper to help store current template settings.  We need to set template
# parameters all over and collect them together in the end.  tt_params does
# what we want, but it has precedence over things you pass in normally on
# actual template building, which means we'd have to use it throughout the
# actual print function as well.  There should be nothing wrong with that, but
# still, I'd rather just create things this way, as it 'feels' cleaner.
# Return the parameter hashref.
sub template_params {
    my ($self, $settings) = @_;

    my $params = $self->param ('template_params');
    if (defined $settings) {
        for my $key (keys %$settings) {
            $params->{$key} = $settings->{$key};
        }
        $self->param ('template_params', $params);
    }

    return $params;
}

# Given a page type, return the template URL from the param hash it's stored
# in.  This could be done as a two-liner everywhere in the code, but it's a
# little more readable to have this do the guts for us.  Returns a string of
# the page template filename, or '' if none found.
sub get_pagename {
    my ($self, $pagetype) = @_;
    my $pages = $self->param ('pages');
    my $pagename = $pages->{$pagetype};
    return $pagename if defined $pagename;

    print STDERR "could not find a page template of type $pagetype\n"
        if $self->param ('logging');
    return '';
}

# Print the headers for a page.  Takes the user's query and any additional
# cookies to set as parameters, and always adds the test cookie.  Skip any
# remuser proxy tokens, since those are internal and we want to reauthenticate
# the user every time.  Takes an optional redirection URL and an optional
# parameter saying that this is a post redirect.
sub print_headers {
    my ($self, $args) = @_;
    my $return_url   = $args->{return_url};
    my $use_303      = $args->{use_303};
    my $confirm_page = $args->{confirm_page};
    my $q            = $self->query;

    # Merge the cookies the browser sent with the ones we got from the WebKDC
    # response in a way that the latter overrides the former.  We want to see
    # the full set for the logic around expiring cookies during a login from a
    # public system to work properly.
    my %cookies;
    my %browser_cookies = CGI::Cookie->fetch;
    while (my ($name, $cookie) = each %browser_cookies) {
        $cookies{$name}{value} = $cookie->value;
    }
    if ($args->{cookies}) {
        for my $name (keys %{ $args->{cookies} }) {
            $cookies{$name} = $args->{cookies}{$name};
        }
    }

    # REMUSER_COOKIE is handled as a special case, since it stores user
    # preferences and should be retained rather than being only a session
    # cookie.  Any cookies sent us with no value should be deleted -- that's
    # how the WebKDC tells us a proxy token is invalid.
    my $remuser_name = $self->param ('remuser_cookie');
    my $remuser_lifetime = $self->param ('remuser_lifetime');
    my $secure = (defined ($ENV{HTTPS}) && $ENV{HTTPS} eq 'on') ? 1 : 0;
    my @ca;
    while (my ($name, $attrs) = each %cookies) {
        next if $name eq 'webauth_wpt_remuser';
        my $value      = $attrs->{value};
        my $expiration = $attrs->{expiration};
        my $cookie;

        # Expire the cookies with no values.
        if (($name =~ /^webauth_wpt/ || $name eq 'webauth_wft') && !$value) {
            $cookie = $self->expire_cookie ($name, $secure);

        # If told not to remember the login, expire the SSO cookies on display
        # of the confirmation page or any final redirect to WAS.
        } elsif ($name =~ /^webauth_wpt_/ && $confirm_page
                 && $self->remember_login eq 'no') {
            $cookie = $self->expire_cookie ($name, $secure);

        # Likewise for any webkdc-factor token.
        } elsif ($name eq 'webauth_wft' && $confirm_page
                 && $self->remember_login eq 'no') {
            $cookie = $self->expire_cookie ($name, $secure);

        # Pass along the remuser cookie and update its expiration.
        } elsif ($name eq $remuser_name) {
            $cookie = $q->cookie (-name    => $name,
                                  -value   => $value,
                                  -secure  => $secure,
                                  -expires => $remuser_lifetime);

        # Pass along a factor token with set lifetime.
        } elsif ($name eq 'webauth_wft') {
            $cookie = $q->cookie (-name    => $name,
                                  -value   => $value,
                                  -secure  => $secure);

            # Set expiration if one is given.
            if ($expiration) {
                my @expires = gmtime ($expiration);
                my $lifetime = strftime ("%a, %d-%b-%Y %T GMT", @expires);
                $cookie->expires ($lifetime);
            }

        # Pass along all other webkdc-proxy and webkdc-factor cookies.
        } elsif ($name =~ /^webauth_w[pf]t/) {
            $cookie = $q->cookie (-name     => $name,
                                  -value    => $value,
                                  -secure   => $secure,
                                  -httponly => 1);
        }

        # Add the cookie to the list of cookies we're setting if we created a
        # new cookie object.
        if (defined $cookie) {
            push (@ca, $cookie);
        }
    }

    # If we haven't been given a webauth factor token cookie explicitly, then
    # we want to expire any that exist.
    if ($self->should_clear_factor && $self->{request}->factor_token) {
        my $cookie = $self->expire_cookie ('webauth_wft', $secure);
        push (@ca, $cookie);
    }

    # Set the test cookie unless it's already set.
    unless ($q->cookie ($self->param ('test_cookie'))) {
        my $cookie = $q->cookie (-name     => scalar $self->param ('test_cookie'),
                                 -value    => 'True',
                                 -secure   => $secure,
                                 -httponly => 1);
        push (@ca, $cookie);
    }

    # Now, print out the page header with the appropriate cookies and with all
    # the HTTP headers required to tell all browser to, no, really, don't
    # cache.
    my @params;
    if ($return_url) {
        push (@params, -location => $return_url,
              -status => $use_303 ? '303 See Also' : '302 Moved');
    }
    push (@params, -cookie => [@ca]) if @ca;
    my $cache_control = 'private, no-cache, no-store, max-age=0';
    $self->header_props (-type => 'text/html', -expires => '-1d',
                         -Pragma => 'no-cache', -Vary => '*',
                         -Cache_Control => $cache_control, @params);
    return '';
}

# Determine what pretty display URL to use from the given return URI object.
#
# This is a bit more complicated if we're using Shibboleth; in that case, try
# to extract a URI from the target parameter of the return URL.  If the target
# value not a valid URL (e.g. when the SP's localRelayState property is true,
# in which case the target value is "cookie"), fall back to using the value of
# the shire parameter, which is the location of the the authentication
# assertion handler.
#
# If we're not using Shibboleth, or if we can't parse the Shibboleth URL and
# find the SP, just return the scheme and host of the return URL.
sub pretty_return_uri {
    my ($self, $uri) = @_;
    my $pretty;
    if (grep { $uri->host eq $_ } @WebKDC::Config::SHIBBOLETH_IDPS) {
        my $dest;
        my $target = $uri->query_param ('target');
        if ($target) {
            $dest = URI->new ($target);
        }
        unless ($dest && $dest->scheme && $dest->scheme =~ /^https?$/) {
            my $shire = $uri->query_param ('shire');
            if ($shire) {
                $dest = URI->new ($shire);
            }
        }
        if ($dest && $dest->scheme && $dest->scheme =~ /^https?$/) {
            $pretty = $dest->scheme . "://" . $dest->host;
        }
    }

    # The non-Shibboleth case.  Just use the scheme and host.
    unless ($pretty) {
        $pretty = $uri->scheme . "://" . $uri->host;
    }

    return $pretty;
}

# Parse the return URL of our request, saving the prettified uri.  Make sure
# that the scheme exists and is a valid WebAuth scheme.  Return 0 if
# everything is okay, 1 if the scheme is invalid.
sub parse_uri {
    my ($self) = @_;
    my $resp = $self->{response};
    my $uri = URI->new ($resp->return_url);
    my $scheme = $uri->scheme;
    unless (defined ($scheme) && $scheme =~ /^https?$/) {
        $self->template_params ({err_webkdc => 1});
        return 1;
    }

    $self->param ('pretty_uri', $self->pretty_return_uri ($uri));
    return 0;
}

# Parse the token.acl file and return a reference to a list of the credentials
# that the requesting WAS is permitted to obtain.  Takes the WebKDC response,
# from which it obtains the requesting identity.
sub token_rights {
    my ($self) = @_;
    my $resp = $self->{response};

    return [] unless $WebKDC::Config::TOKEN_ACL;
    unless (open (ACL, '<', $WebKDC::Config::TOKEN_ACL)) {
        return [];
    }
    my $requester = $resp->requester_subject;
    my $rights = [];
    local $_;
    while (<ACL>) {
        s/\#.*//;
        next if /^\s*$/;
        my ($id, $token, $type, $name) = split;
        next unless $token eq 'cred';
        next unless $id =~ s/^krb5://;
        $id = quotemeta $id;
        $id =~ s/\\*/[^\@]*/g;
        next unless $requester =~ /$id/;
        my $data = {};
        $data->{type} = $type;
        $data->{name} = $name;
        if ($type eq 'krb5') {
            my ($principal, $realm) = split ('@', $name, 2);
            my $instance;
            ($principal, $instance) = split ('/', $principal, 2);
            $data->{principal} = $principal;
            $data->{instance}  = $instance;
            $data->{realm}     = $realm;
        }
        push (@$rights, $data);
    }
    close ACL;
    return $rights;
}

# Obtains the login cancel URL and sets appropriate parameters in the login
# page if one is present.
#
# FIXME: Duplicates some of the logic of print_confirm_page but uses slightly
# different template parameters.  This is annoying and should be standardized.
sub get_login_cancel_url {
    my ($self) = @_;
    my $resp = $self->{response};
    my $lc = $resp->login_canceled_token;
    my $cancel_url;

    # FIXME: Looks like extra semicolons here too.
    if ($lc) {
        $cancel_url = $resp->return_url . "?WEBAUTHR=$lc;";
        $cancel_url .= ";WEBAUTHS=" . $resp->app_state . ";"
            if $resp->app_state;
    }
    if ($cancel_url) {
        $self->template_params ({login_cancel => 1});
        $self->template_params ({cancel_url => $cancel_url});
    }

    return 0;
}

##############################################################################
# Actual page views
##############################################################################

# Print the login page.  Takes the query, the variable hash, the error code if
# any, the WebKDC response, the request token, and the service token, and
# encodes them as appropriate in the login page.
sub print_login_page {
    my ($self, $err, $RT, $ST) = @_;
    my $q = $self->query;

    my $pagename = $self->get_pagename ('login');
    my $params = $self->template_params;
    $params->{script_name} = $self->param ('script_name');
    $params->{username} = $q->param ('username');
    $params->{RT} = $RT;
    $params->{ST} = $ST;
    $params->{remember_login} = $self->remember_login;
    if ($self->param ('remuser_url')) {
        $params->{show_remuser} = 1;
        $params->{remuser_url} = $self->param ('remuser_url');
    }
    if ($self->param ('remuser_failed')) {
        $params->{remuser_failed} = 1;
    }

    # If and only if we got here as the target of a form submission (meaning
    # that they already had one shot at logging in and something didn't work),
    # set the appropriate error status.
    #
    # If they *haven't* already had one shot and forced login is set, display
    # the error box telling them they're required to log in.
    if ($q->param ('login')) {
        $params->{err_password} = 1 unless $q->param ('password');
        $params->{err_username} = 1 unless $q->param ('username');
        $params->{err_missinginput} = 1 if $params->{'err_username'};
        $params->{err_missinginput} = 1 if $params->{'err_password'};
        if ($err == WK_ERR_LOGIN_FAILED) {
            $params->{err_loginfailed} = 1;
        }
        if ($err == WK_ERR_USER_REJECTED) {
            $params->{err_rejected} = 1;
        }

        # Set a generic error indicator if any of the specific ones were set
        # to allow easier structuring of the login page template.
        $params->{error} = 1 if $params->{'err_missinginput'};
        $params->{error} = 1 if $params->{'err_loginfailed'};
        $params->{error} = 1 if $params->{'err_rejected'};
    } elsif ($self->param ('forced_login')) {
        $params->{err_forced} = 1;
        $params->{error} = 1;
    }

    my %args = (cookies => $self->{response}->cookies);
    $self->print_headers (\%args);
    my $content = $self->tt_process ($pagename, $params);
    if ($content) {
        return $content;
    } else {
        $self->print_error_fatal ('could not process login template');
    }
}

# Print an error page, making sure that error pages are never cached.
sub print_error_page {
    my ($self) = @_;
    my $pagename = $self->get_pagename ('error');
    my $resp = $self->{response};
    my $params = $self->template_params;
    my $q = $self->query;

    # If there is a login cancel option, handle creating the link for it.
    my $lc = $resp->login_canceled_token;
    if (defined $lc) {
        $params->{login_cancel} = 1;
        my $cancel_url = $resp->return_url;

        # FIXME: Looks like extra semicolons here too.
        $cancel_url .= "?WEBAUTHR=$lc;";
        $cancel_url .= ";WEBAUTHS=" . $resp->app_state . ";"
            if $resp->app_state;
        $params->{cancel_url} = $cancel_url;
    }

    # If the user has been locked out due to hitting the rate limit, force
    # expiration of any persistent factor cookies and proxy cookies by marking
    # this as a public computer.
    if ($params->{err_lockout}) {
        $q->param ('remember_login', 'no');
    }

    # Print out the error page.
    my %args = (cookies => $resp->cookies);
    $self->print_headers (\%args);
    my $content = $self->tt_process ($pagename, $params);
    if ($content) {
        return $content;
    } else {
        $self->print_error_fatal ('could not process error template');
    }
}

# In case of a fatal error, such as being unable to process a template, we
# either print out a given 500 error page, or die to have Apache handle it
# for us.
sub print_error_fatal {
    my ($self, $error) = @_;
    my $q = $self->query;

    if ($WebKDC::Config::FATAL_PAGE && -f $WebKDC::Config::FATAL_PAGE
        && open (FATAL, '<', $WebKDC::Config::FATAL_PAGE)) {

        warn ($error);
        my $page = '';
        while (<FATAL>) {
            $page .= $_;
        }
        return $page;
    } else {
        die ($error);
    }
}

# Given the query, the local variables, and the WebKDC response, print the
# confirmation page, filling in all of the various bits of data that the page
# template needs.
#
# Setting the runmode occurs in the actual template file.
sub print_confirm_page {
    my ($self) = @_;

    my $q                 = $self->query;
    my $resp              = $self->{response};
    my $pagename          = $self->get_pagename ('confirm');
    my $params            = $self->template_params;

    my $uri               = URI->new ($resp->return_url);
    my $pretty_return_url = $self->pretty_return_uri ($uri);
    my $return_url        = $resp->return_url;
    my $token_type        = $resp->response_token_type;
    my $user_message      = $self->{response}->user_message;

    # The code to return the response token type was added in WebAuth 3.6.1.
    # Provide a useful error message if the mod_webkdc is older than that.
    unless (defined $token_type) {
        warn 'token type not present in WebKDC response; mod_webkdc on the'
            . " WebKDC may be older than 3.6.1\n";
        $token_type = '';
    }

    # We saw one error in production where this function was called after an
    # apparently successful WebKDC interaction, but there was no response
    # token.  Make a sanity check for that case.
    if (!$resp->response_token) {
        return $self->print_error_fatal ('token missing in WebKDC response');
    }

    # FIXME: This looks like it generates extra, unnecessary semicolons, but
    # should be checked against the parser in the WebAuth module.
    $return_url .= "?WEBAUTHR=" . $resp->response_token . ";";
    $return_url .= ";WEBAUTHS=" . $resp->app_state . ";" if $resp->app_state;

    # Find out if the user is within the window to have a password warning.
    # Present this warning only if the request was a POST, indicating that the
    # user provided some authentication credentials.  This avoids warning
    # (and, more importantly, inserting a confirmation screen) if the user
    # otherwise could have just been redirected to the destination without any
    # WebLogin interaction, such as via REMOTE_USER or a single sign-on
    # cookie.
    my $expire_warning = 0;
    if ($q->request_method eq 'POST' && $WebKDC::Config::EXPIRING_PW_URL) {
        my $expiring = $resp->password_expiration;
        if (defined ($expiring)
            && (($expiring - time) < $WebKDC::Config::EXPIRING_PW_WARNING)) {

            # Set template variable for expiring password.
            # TODO: Remove expire_date after giving time to update templates.
            $expire_warning = 1;
            my $expire_date = localtime ($expiring);
            $params->{warn_expire} = 1;
            $params->{expire_date}      = $expire_date;
            $params->{expire_timestamp} = $expiring;
            $params->{pwchange_url}     = $WebKDC::Config::EXPIRING_PW_URL;

            # Create and set the kadmin/changepw token (unless we require the
            # user re-enter).
            if (!$WebKDC::Config::EXPIRING_PW_RESEND_PASSWORD) {
                $self->add_changepw_token;
                $params->{CPT} = $self->param ('CPT');
            } else {
                $params->{skip_username} = 1;
            }
        }
    }

    # Determine if a device factor cookie is about to expire, and set the
    # time at which it expires if so.
    my $factor_warning = 0;
    my $cookies = $resp->cookies;
    if ($cookies) {
        while (my ($name, $attrs) = each %{$cookies}) {
            next unless $name eq 'webauth_wft';
            my $expiration = $attrs->{expiration};
            if ($WebKDC::Config::FACTOR_WARNING + time > $expiration) {
                $factor_warning = 1;
                $params->{device_expiring} = $expiration;
            }
        }
    }

    # If configured to permit bypassing the confirmation page, the WAS
    # requested an id token (not a proxy token, which may indicate ticket
    # delegation), and the page was not the target of a POST, return a
    # redirect to the final page instead of displaying a confirmation page.
    # If the page was the target of the post, we'll return a 303 redirect
    # later on but present the regular confirmation page as the body in case
    # the browser doesn't support it.
    #
    # We also skip the bypass if the user has an upcoming password expiration
    # warning, if they have a login history from the WebKDC that needs to be
    # displayed due to suspicious activity, or if they've asserted an
    # authorization identity.
    my $post = ($q->request_method eq 'POST') ? 1 : 0;
    my $history = $resp->login_history;
    my $bypass = $WebKDC::Config::BYPASS_CONFIRM;
    $bypass = 0 if $expire_warning;
    $bypass = 0 if $factor_warning;
    $bypass = 0 if $history;
    $bypass = 0 if $resp->authz_subject;
    $bypass = 0 if $resp->permitted_authz;
    $bypass = 0 if $user_message;
    if ($bypass and $bypass eq 'id') {
        $bypass = ($token_type eq 'id') ? 1 : 0;
    }
    if ($token_type eq 'id') {
        if ($bypass and not $post) {
            my %args = (cookies      => $resp->cookies,
                        return_url   => $return_url,
                        confirm_page => 1);
            return $self->print_headers (\%args);
        }
    }

    # Find our page and set general template parameters.
    $params->{return_url}        = $return_url;
    $params->{username}          = $resp->subject;
    $params->{authz_subject}     = $resp->authz_subject;
    $params->{permitted_authz}   = [ $resp->permitted_authz ];
    $params->{pretty_return_url} = $pretty_return_url;
    $params->{token_rights}      = $self->token_rights;
    $params->{history}           = $history;
    $params->{user_message}      = $user_message;
    $params->{remember_login}    = $self->remember_login;
    $params->{ST}                = $q->param ('ST');
    $params->{RT}                = $q->param ('RT');

    # Create the login_state object for use in templates
    if ($self->{response}->login_state) {
        my $login_state = $self->{response}->login_state;
        $params->{LS} = $login_state;
        $params->{login_state} = $self->parse_login_state($login_state);
    }

    # If there is a login cancel option, handle creating the link for it.
    my $lc = $resp->login_canceled_token;
    if (defined $lc) {
        $params->{login_cancel} = 1;
        my $cancel_url = $resp->return_url;

        # FIXME: Looks like extra semicolons here too.
        $cancel_url .= "?WEBAUTHR=$lc;";
        $cancel_url .= ";WEBAUTHS=" . $resp->app_state . ";"
            if $resp->app_state;
        $params->{cancel_url} = $cancel_url;
    }

    # If REMOTE_USER is done at a separate URL *and* REMOTE_USER support was
    # either requested or used, show the checkbox for it.
    if ($WebKDC::Config::REMUSER_REDIRECT) {
        my $cookie_name = $self->param ('remuser_cookie');
        if ($ENV{REMOTE_USER} || $q->cookie ($cookie_name)) {
            $params->{show_remuser} = 1;
            $params->{script_name} = $self->param ('script_name');

            $params->{remuser} = 1 if $q->cookie ($cookie_name);
        }
    }

    # Print out the page, including any updated proxy cookies if needed.  If
    # we're suppressing the confirm page and the browser used HTTP/1.1, use
    # the HTTP 303 redirect code as well.
    if ($bypass && $ENV{SERVER_PROTOCOL} eq 'HTTP/1.1') {
        my %args = (cookies      => $resp->cookies,
                    return_url   => $return_url,
                    use_303      => 1,
                    confirm_page => 1);
        $self->print_headers (\%args);
    } else {
        my %args = (cookies      => $resp->cookies,
                    confirm_page => 1);
        $self->print_headers (\%args);
    }
    my $content = $self->tt_process ($pagename, $params);
    if ($content) {
        return $content;
    } else {
        $self->print_error_fatal ('could not process confirm template');
    }
}

# Given the query, redisplay the confirmation page after a change in the
# REMOTE_USER cookie.  Also set the new REMOTE_USER cookie.
#
# FIXME: We lose the token rights.  Maybe we should preserve the identity of
# the WAS in a hidden variable?
sub redisplay_confirm_page {
    my ($self) = @_;
    my $q = $self->query;

    my $username = $q->param ('username');
    my $return_url = $q->param ('return_url');
    my $uri = URI->new ($return_url);
    unless ($username && $uri && $uri->scheme && $uri->host) {
        $self->template_params ({err_confirm => 1});
        print STDERR "missing data when reconstructing confirm page\n"
            if $self->param ('logging');
        return $self->print_error_page;
    }
    my $pretty_return_url = $self->pretty_return_uri ($uri);

    # Find our page and set general template parameters.
    my $pagename = $self->get_pagename ('confirm');
    my $params = $self->template_params;
    $params->{return_url} = $return_url;
    $params->{username} = $username;
    $params->{pretty_return_url} = $pretty_return_url;
    $params->{script_name} = $self->param ('script_name');
    $params->{show_remuser} = 1;
    my $remuser = $q->param ('remuser') eq 'on' ? 'checked' : '';
    $params->{remuser} = $remuser;
    $params->{remember_login} = $self->remember_login;
    $params->{ST} = $q->param ('ST');
    $params->{RT} = $q->param ('RT');
    $params->{LS} = $q->param ('LS');

    # If there is a login cancel option, handle creating the link for it.
    my $cancel_url = $q->param ('cancel_url');
    if (defined $cancel_url) {
        $params->{login_cancel} = 1;
        $params->{cancel_url} = $cancel_url;
    }

    # Create a hash for the REMOTE_USER cookie.
    my $cookie_name = $self->param ('remuser_cookie');
    my $cookie_val  = $remuser ? 1 : 0;
    my %cookie = ($cookie_name => { value      => $cookie_val,
                                    expiration => 0});

    # Print out the page, including the new REMOTE_USER cookie.
    my %args = (cookies => \%cookie);
    $self->print_headers (\%args);
    my $content = $self->tt_process ($pagename, $params);
    if ($content) {
        return $content;
    } else {
        $self->print_error_fatal ('could not process confirm template');
    }
}

# Print the password change page.
sub print_pwchange_page {
    my ($self, $RT, $ST) = @_;
    my $q = $self->query;
    my $pagename = $self->get_pagename ('pwchange');
    my $params = $self->template_params;

    # Get and pass along various field values that remain across attempts.
    $params->{username} = $q->param ('username');
    $params->{CPT} = $self->param ('CPT');
    $params->{RT} = $RT;
    $params->{ST} = $ST;
    $params->{remember_login} = $self->remember_login;
    $params->{script_name} = $self->param ('script_name');
    $params->{expired} = 1
        if ($q->param ('expired') and $q->param ('expired') eq '1');

    # We don't need the user information if they have already acquired a
    # kadmin/changepw token, or at previous request to skip the username.
    if ($self->param ('CPT')) {
        $params->{skip_username} = 1;
        $params->{skip_password} = 1;
    } elsif (defined $q->param ('skip_username')
             && $q->param ('skip_username') == 1) {
        $params->{skip_username} = 1;
    }

    # Print out the page.
    $self->print_headers;
    my $content = $self->tt_process ($pagename, $params);
    if ($content) {
        return $content;
    } else {
        $self->print_error_fatal ('could not process pwchange template');
    }
}

# Print confirmation page after successful password change.  This is only
# hit when not having been sent here with an expired password.  We don't set
# a runmode, since this is an end state.
sub print_pwchange_confirm_page {
    my ($self) = @_;
    my $q = $self->query;
    my $pagename = $self->get_pagename ('pwchange');
    my $params = $self->template_params;

    $params->{success} = 1;
    $self->print_headers;
    my $content = $self->tt_process ($pagename, $params);
    if ($content) {
        return $content;
    } else {
        $self->print_error_fatal ('could not process pwchange confirm '
                                  .'template');
    }
}

# Print the page prompting a user to give a multifactor OTP.  This is called
# whenever the user's login attempt returns that multifactor should be tried,
# or on an unsuccessful attempt to use multifactor.
sub print_multifactor_page {
    my ($self, $RT, $ST) = @_;

    my $q                     = $self->query;
    my $pagename              = $self->get_pagename ('multifactor');

    my $params                = $self->template_params;
    $params->{script_name}    = $self->param ('script_name');
    $params->{username}       = $q->param ('username');
    $params->{remember_login} = $self->remember_login;
    $params->{user_message}   = $self->{response}->user_message;
    $params->{RT}             = $RT;
    $params->{ST}             = $ST;

    # Default the factor type to anything saved from the previous page.
    $params->{factor_type} = $q->param ('factor_type');

    # Find just the o* factor to pass along to the template for any special
    # processing.  Start by looking for any o* configured factor.  This will
    # pick the last of the available o* configured factors.  Then, override
    # that with the desired factor if it wants something more specific.
    if ($self->{response}->factor_configured) {
        for my $factor (@{$self->{response}->factor_configured}) {
            next unless $factor =~ /^o\d+$/;
            $params->{factor_type} = $factor;
        }
    }
    if ($self->{response}->factor_needed) {
        foreach my $factor (@{$self->{response}->factor_needed}) {
            next unless $factor =~ /^o\d+$/;
            $params->{factor_type} = $factor;
        }
    }

    # Add the devices, or restore from an earlier send.  Since the devices
    # are a complicated datastructure, we save a string version for future
    # iterations of this page.
    $params->{default_device} = $self->{response}->default_device
        || $q->param('default_device');
    $params->{default_factor} = $self->{response}->default_factor
        || $q->param('default_factor');
    if ($q->param('devices_cache')) {
        ($params->{devices}) = thaw($q->param('devices_cache'));
        $params->{devices_cache} = $q->param('devices_cache');
    } else {
        my $devices              = $self->{response}->devices;
        $params->{devices}       = $devices;
        $params->{devices_cache} = freeze($devices);
    }

    # Create the login_state object for use in templates
    if ($self->{response}->login_state) {
        my $login_state = $self->{response}->login_state;
        $params->{LS} = $login_state;
        $params->{login_state} = $self->parse_login_state($login_state);
    }

    $params->{error} = 1 if $params->{'err_multifactor_missing'};
    $params->{error} = 1 if $params->{'err_multifactor_invalid'};
    $params->{error} = 1 if $params->{'err_multifactor_timeout'};

    my %args = (cookies => $self->{response}->cookies);
    $self->print_headers (\%args);
    my $content = $self->tt_process ($pagename, $params);
    if ($content) {
        return $content;
    } else {
        $self->print_error_fatal ('could not process multifactor template');
    }
}

##############################################################################
# REMOTE_USER support
##############################################################################

# Redirect the user to the REMOTE_USER-enabled login URL.
sub print_remuser_redirect {
    my ($self) = @_;
    my $q = $self->query;
    my $uri = $WebKDC::Config::REMUSER_REDIRECT;

    unless ($uri) {
        print STDERR "REMUSER_REDIRECT not configured\n"
            if $self->param ('logging');
        $self->template_params ({err_webkdc => 1});
        my $errmsg = "unrecoverable error occured. Try again later.";
        $self->template_params ({err_msg => $errmsg});
        return $self->print_error_page;
    } else {
        $uri .= "?RT=" . $self->fix_token (scalar $q->param ('RT')) .
                ";ST=" . $self->fix_token (scalar $q->param ('ST'));
        print STDERR "redirecting to $uri\n" if $self->param ('debug');
        return $self->redirect ($uri);
    }
}

# Generate a proxy token using forwarded Kerberos credentials and pass it into
# the WebKDC with the other proxy tokens.
sub add_kerberos_proxy_token {
    my ($self) = @_;

    print STDERR "adding a proxy token for $ENV{REMOTE_USER}\n"
        if $self->param ('debug');
    my ($kreq, $data);
    my $principal = $WebKDC::Config::WEBKDC_PRINCIPAL;
    eval {
        my $context = $self->{webauth}->krb5_new;
        $context->init_via_cache;
        my ($tgt, $expires) = $context->export_cred;
        ($kreq, $data) = $context->make_auth ($principal, $tgt);
        $kreq = encode_base64 ($kreq, '');
        $data = encode_base64 ($data, '');
    };
    if ($@) {
        print STDERR "failed to create proxy token request for"
            . " $ENV{REMOTE_USER}: $@\n" if $self->param ('logging');
        return;
    }
    my ($status, $error, $token, $subject)
        = WebKDC::make_proxy_token_request ($kreq, $data);
    if ($status != WK_SUCCESS) {
        print STDERR "failed to obtain proxy token for $ENV{REMOTE_USER}:"
            . " $error\n" if $self->param ('logging');
        return;
    }
    print STDERR "adding krb5 proxy token for $subject\n"
        if $self->param ('debug');
    $self->{request}->proxy_cookie ('krb5', $token, 'k');
}

# Add a generic token to the set of tokens that we'll pass to the WebKDC.
# This function takes a reference to a hash of parameters as follows:
#
# proxy_type      - Proxy type of resulting token (default: remuser)
# proxy_subject   - Proxy subject of resulting token (default: WEBKDC:remuser)
# subject         - Authenticated identity of user
# expiration      - Expiration time (default: time + REMUSER_EXPIRES)
# initial_factors - Initial authentication factors (default: u)
# session_factors - Session authentication factors (default: u)
# loa             - Level of assurance (default: 0)
#
# The resulting token will be stored in the set of cookies in the WebKDC
# request.
#
# Returns: undef
sub add_generic_proxy_token {
    my ($self, $args_ref) = @_;
    my %args = %{$args_ref};
    my $wa   = $self->{webauth};

    # Set token defaults.
    $args{proxy_type}      ||= 'remuser';
    $args{proxy_subject}   ||= 'WEBKDC:remuser';
    $args{expiration}      ||= time + $WebKDC::Config::REMUSER_EXPIRES;
    $args{initial_factors} ||= 'u';
    $args{session_factors} ||= 'u';

    # Load the keyring we'll use for token encoding.
    use Carp;
    confess("null $wa") unless defined $wa;
    my $keyring = $wa->keyring_read ($WebKDC::Config::KEYRING_PATH);
    unless ($keyring) {
        warn "weblogin: unable to initialize a keyring from"
            . " $WebKDC::Config::KEYRING_PATH\n";
        return;
    }

    # Create a proxy token.
    my $token = WebAuth::Token::WebKDCProxy->new ($wa);
    $token->subject ($args{subject});
    $token->proxy_type ($args{proxy_type});
    $token->proxy_subject ($args{proxy_subject});
    $token->data ($args{subject});
    $token->expiration ($args{expiration});
    $token->initial_factors ($args{initial_factors});
    if (defined ($args{loa}) && $args{loa} > 0) {
        $token->loa ($args{loa});
    }

    # Add the token to the WebKDC request.
    my $token_string = $token->encode ($keyring);
    my $factors      = $args{session_factors};
    $self->{request}->proxy_cookie ('remuser', $token_string, $factors);
    return;
}

# Generate a proxy token containing the REMOTE_USER identity and pass it into
# the WebKDC along with the other proxy tokens.  Takes the request to the
# WebKDC that we're putting together.  If the REMOTE_USER isn't valid for some
# reason, log an error and don't do anything else.
sub add_remuser_token {
    my ($self) = @_;
    my $wa = $self->{webauth};

    print STDERR "adding a REMOTE_USER token for $ENV{REMOTE_USER}\n"
        if $self->param ('debug');

    # Make sure that any realm in REMOTE_USER is permitted.
    my $identity = $ENV{REMOTE_USER};
    my ($user, $realm) = split ('@', $identity, 2);
    if (@WebKDC::Config::REMUSER_PERMITTED_REALMS) {
        my $found = 0;
        $realm ||= '';
        for my $check (@WebKDC::Config::REMUSER_PERMITTED_REALMS) {
            if ($check eq $realm) {
                $found = 1;
                last;
            }
        }
        if (!$found) {
            warn "weblogin: realm mismatch in REMOTE_USER $ENV{REMOTE_USER}:"
                . ' saw ' . ($realm ? $realm : '""') . ' not in allowed list'
                . "\n";
            return;
        }
    }
    if (grep { $realm eq $_ } @WebKDC::Config::REMUSER_LOCAL_REALMS) {
        $identity = $user;
    }

    # If there's a callback defined for determining the initial and session
    # factors and level of assurance, make that callback.
    my ($ini, $sess, $loa);
    if (defined (&WebKDC::Config::remuser_factors)) {
        ($ini, $sess, $loa) = WebKDC::Config::remuser_factors ($identity);
    }

    # Add the token to the WebKDC request.
    $self->add_generic_proxy_token(
        {
            subject         => $identity,
            initial_factors => $ini,
            session_factors => $sess,
            loa             => $loa,
        }
    );
}

##############################################################################
# Password change functions
##############################################################################

# Create a kadmin/changepw token using the username and password.  Returns
# true on success and false on failure.
sub add_changepw_token {
    my ($self) = @_;
    my $wa = $self->{webauth};
    my $q = $self->query;
    my $username = $q->param ('username');
    my $password = $q->param ('password');

    # Don't bother if the token already is created.
    return 1 if $self->param ('CPT');

    print STDERR "adding a kadmin/changepw cred token for $username\n"
        if $self->param ('debug');

    # Create a ticket for the password change principal with the username and
    # password.
    my ($ticket, $expires, $changepw);
    if ($WebKDC::Config::PASSWORD_CHANGE_SERVER) {
        $changepw = $WebKDC::Config::PASSWORD_CHANGE_PRINC;
    }
    $changepw ||= 'kadmin/changepw';
    if ($WebKDC::Config::DEFAULT_REALM && $changepw !~ /\@/) {
        $changepw .= '@' . $WebKDC::Config::DEFAULT_REALM;
    }
    eval {
        my $context = $wa->krb5_new;
        $context->init_via_password ($username, $password, $changepw);
        ($ticket, $expires) = $context->export_cred ($changepw);
    };
    if ($@) {
        print STDERR "failed to create $changepw credential for $username:"
            . " $@\n" if $self->param ('logging');
        return;
    }

    # Token expires the sooner of when the ticket expires or our time limit.
    my $expires_limit = time + $CHANGEPW_EXPIRES;
    $expires = $expires_limit if $expires_limit < $expires;

    # Create the token to contain the credential.
    my $token = WebAuth::Token::Cred->new ($wa);
    $token->subject ($username);
    $token->type ('krb5');
    $token->service ($changepw);
    $token->data ($ticket);
    $token->creation (time);
    $token->expiration ($expires);

    # Add the token to the web page.
    my $keyring = $wa->keyring_read ($WebKDC::Config::KEYRING_PATH);
    unless ($keyring) {
        warn "weblogin: unable to initialize a keyring from"
            . " $WebKDC::Config::KEYRING_PATH\n";
        return;
    }
    $self->param ('CPT', $token->encode ($keyring));
    return 1;
}

# Attempt to change the user password using the changepw token.
sub change_user_password {
    my ($self) = @_;
    my $wa = $self->{webauth};
    my $q = $self->query;
    my ($status, $error);

    my $username = $q->param ('username');
    my $password = $q->param ('new_passwd1');
    my $cpt = $self->param ('CPT');

    print STDERR "changing password for $username\n"
        if $self->param ('debug');

    my $keyring = $wa->keyring_read ($WebKDC::Config::KEYRING_PATH);
    unless ($keyring) {
        warn "weblogin: unable to initialize a keyring from"
            . " $WebKDC::Config::KEYRING_PATH\n";
        return;
    }

    # Decode the credential token with keyring and token, then verify token
    # validity.  If we don't yet have a CPT, but do have the user's old
    # password (ie: they came straight to the change password page), create
    # one right now.  If there's an error actually decrypting the token, it's
    # likely expired.  Hide the actual error behind a simpler one for the
    # user.
    if (!$cpt && $q->param ('password')) {
        unless ($self->add_changepw_token) {
            return (WK_ERR_LOGIN_FAILED,
                    'cannot acquire passord change credentials');
        }
        $cpt = $self->param ('CPT');
    }
    my $token = eval { $wa->token_decode ($cpt, $keyring) };
    if ($@) {
        $self->param ('CPT', '');
        my $msg = "internal error";
        my $e = $@;
        if (ref $e and $e->isa('WebKDC::WebKDCException')) {
            print STDERR $e->message(), "\n" if $self->param ('logging');
            return ($e->status(), $msg);
        } elsif (ref $e and $e->isa('WebAuth::Exception')) {
            print STDERR "WebAuth exception while changing password: $e\n"
                if $self->param ('logging');
            if ($e->{status} == WA_ERR_TOKEN_EXPIRED) {
                $msg = "failed to change password for $username:"
                    . " timed out, re-enter old password";
            }
            return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $msg);
        } elsif ($e) {
            return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $msg);
        }
    } elsif (!$token->isa ('WebAuth::Token::Cred')) {
        my $e = "failed to change password for $username: "
            . 'CPT parameter is not a cred token';
        print STDERR $e, "\n" if $self->param ('logging');
        return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $e);
    } elsif ($token->subject ne $username) {
        my $e = "failed to change password for $username: invalid username";
        print STDERR $e, "\n" if $self->param ('logging');
        return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $e);
    } elsif ($token->type ne 'krb5') {
        my $e = "failed to change password for $username: "
            . "invalid credential type";
        print STDERR $e, "\n" if $self->param ('logging');
        return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $e);
    }

    # Change the password and return any error status plus exception object.
    my $changepw;
    if ($WebKDC::Config::PASSWORD_CHANGE_SERVER) {
        $changepw = $WebKDC::Config::PASSWORD_CHANGE_PRINC;
    }
    $changepw ||= 'kadmin/changepw';
    if ($WebKDC::Config::DEFAULT_REALM && $changepw !~ /\@/) {
        $changepw .= '@' . $WebKDC::Config::DEFAULT_REALM;
    }
    eval {
        my $context = $wa->krb5_new;
        $context->import_cred ($token->data);
        my $args = { protocol => 'kpasswd' };
        if ($WebKDC::Config::PASSWORD_CHANGE_SERVER) {
            $args = {
                protocol   => 'remctl',
                host       => $WebKDC::Config::PASSWORD_CHANGE_SERVER,
                port       => $WebKDC::Config::PASSWORD_CHANGE_PORT,
                identity   => $changepw,
                command    => $WebKDC::Config::PASSWORD_CHANGE_COMMAND,
                subcommand => $WebKDC::Config::PASSWORD_CHANGE_SUBCOMMAND,
            };
        }
        $context->change_password ($password, $args);
    };
    my $e = $@;
    if (ref $e and $e->isa('WebKDC::WebKDCException')) {
        return ($e->status(), $e->message());
    } elsif (ref $e and $e->isa('WebAuth::Exception')) {
        return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $e->error_message);
    } elsif ($e) {
        return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $e);
    } else {
        return (WebKDC::WK_SUCCESS, undef);
    }
}

##############################################################################
# Test for various invalid requests
##############################################################################

# Check for cookies being enabled in the browser.
#
# If no cookies are found, this is either the first visit or cookies are
# disabled.  To determine which, reload the page as if we'd not already
# been here, but appending a flag to the URL indicating that we've tried
# to set a cookie.  The cookie should always be present the second time
# around.
#
# However, do not do this as the result of a POST; not only may it violate
# the HTTP/1.0 protocol for browsers that don't support 1.1, but if the
# user already got the login page, it's not clear how they couldn't have
# cookie support.  If we redirect them and strip out the username and
# password, we get a confusing error message or we have to throw the no
# cookie support error page.  Just continue on at that point and hope
# everything works.  We may be dealing with an automated script that wants
# to authenticate via POST without going through the test cookie dance.
#
# If the parameter is already set and we still don't have a cookie, the
# user has cookies disabled.  Display the error page.
sub error_if_no_cookies {
    my ($self) = @_;

    return undef if $self->query->cookie ($self->param ('test_cookie'));
    if (defined $self->query->param ('test_cookie')) {
        print STDERR "no cookie, even after redirection\n"
            if $self->param ('logging');
        $self->template_params ({err_cookies_disabled => 1});
        return $self->print_error_page;
    } elsif ($self->query->request_method ne 'POST') {
        $self->query->delete ('username', 'password', 'submit');
        $self->query->param (test_cookie => 1);
        my $return_url = $self->query->url (-query => 1);
        print STDERR "no cookie set, redirecting to $return_url\n"
            if $self->param ('debug');
        my %args = (return_url => $return_url);
        return $self->print_headers (\%args);
    } else {
        return undef;
    }
}

# If the user sent a password, force POST as a method.  Otherwise, if we
# continue, the password may show up in referrer strings sent by the
# browser to the remote site.
sub error_password_no_post {
    my ($self) = @_;
    my $q = $self->query;

    return undef unless $q->param ('password')
        && $q->request_method ne 'POST';

    $self->template_params ({err_bad_method => 1});
    return $self->print_error_page;
}

# Check to see if we have request and webkdc-service tokens.  If not, display
# the error page and tell the caller to skip to the next request.  Returns
# undef on success and the page text on failure.
sub error_no_request_token {
    my ($self) = @_;
    my $q = $self->query;

    if ($q->param ('RT') && $q->param ('ST')) {
        return;
    } else {
        $self->template_params ({err_no_request_token => 1});
        print STDERR "no request or service token\n"
            if $self->param ('logging');
        return $self->print_error_page;
    }
}

# Test for requirements of a password request:
#   Username (Unless already authed)
#   Current password (Unless already authed)
#   Two prompts for new password (must match)
#
# Check to see if all required fields for a password change form have been
# filled out correctly.  If so, return 1.  If not, print the password
# change page again, with the errors, and return 0.
sub error_invalid_pwchange_fields {
    my ($self) = @_;
    my $q = $self->query;
    my $error;

    # Even if it's a hidden field and not given to user, this should exist.
    if (!$q->param ('username')) {
        $self->template_params ({err_username => 1});
        $error = 1;
    }

    # For password, we do not require it if we already have a kadmin/changepw
    # token.
    if (!$q->param ('password') && !$self->param ('CPT')) {
        $self->template_params ({err_password => 1});
        $error = 1;

    # Check both for empty new password, and for it to not match itself.
    } elsif (!$q->param ('new_passwd1') || !$q->param ('new_passwd2')) {
        $self->template_params ({err_newpassword => 1});
        $error = 1;
    } elsif ($q->param ('new_passwd1') ne $q->param ('new_passwd2')) {
        $self->template_params ({err_newpassword_match => 1});
        $error = 1;
    }

    return undef unless $error;

    # Mark us as having had an error and print the page again.
    $self->template_params ({error => 1});
    return $self->print_pwchange_page ($q->param ('RT'), $q->param ('ST'));
}

##############################################################################
# Rate limiting and replay caching
##############################################################################

# Check whether a given request is a replay.  Takes the request token and
# returns true if it is a replay, false otherwise (including if we aren't
# checking for replays).
sub is_replay {
    my ($self, $rt) = @_;
    if (!$self->{memcache} || !$WebKDC::Config::REPLAY_TIMEOUT) {
        return;
    }
    my $hash = Digest::SHA::sha512_base64 ($rt);
    print STDERR "Looking up request token hash $hash\n"
        if $self->param ('debug');
    my $seen = $self->{memcache}->get ("rt:$hash");
    if ($seen) {
        print STDERR "Rejecting request token $rt as a replay, last seen "
            . strftime ('%Y-%m-%d %T', localtime $seen) . "\n"
            if $self->param ('logging');
        print STDERR "Replacing request token hash $hash\n"
            if $self->param ('debug');
        my $now = time;
        my $expires = $now + $WebKDC::Config::REPLAY_TIMEOUT;
        $self->{memcache}->replace ("rt:$hash", $now, $expires);
        return 1;
    }
    return;
}

# Check whether a given username is rate limited.  Takes the username and
# returns true if they are, false otherwise (including if we aren't doing rate
# limiting).
sub is_rate_limited {
    my ($self, $username) = @_;
    if (!$self->{memcache} || !$WebKDC::Config::RATE_LIMIT_THRESHOLD) {
        return;
    }
    my $count = $self->{memcache}->get ("fail:$username");
    if (defined $count && $count >= $WebKDC::Config::RATE_LIMIT_THRESHOLD) {
        print STDERR "Rate limited authentication for $username\n"
            if $self->param ('logging');
        return 1;
    }
    return;
}

# Register a successful authentication using a request token so that we can
# detect if it is replayed.  Takes the request token and the username.
sub register_auth {
    my ($self, $rt, $username) = @_;
    if (!$self->{memcache} || !$WebKDC::Config::REPLAY_TIMEOUT) {
        return;
    }
    my $hash = Digest::SHA::sha512_base64 ($rt);
    print STDERR "Storing request token hash $hash\n"
        if $self->param ('debug');
    my $now = time;
    my $timeout = $now + $WebKDC::Config::REPLAY_TIMEOUT;
    $self->{memcache}->set ("rt:$hash", $now, $timeout);
    if ($WebKDC::Config::RATE_LIMIT_THRESHOLD) {
        $self->{memcache}->delete ("fail:$username");
    }
}

# Register a failed authentication for rate limiting.  Takes the username.
sub register_auth_fail {
    my ($self, $username) = @_;
    if (!$self->{memcache} || !$WebKDC::Config::RATE_LIMIT_THRESHOLD) {
        return;
    }
    print STDERR "Storing $username authentication failure for rate limit\n"
        if $self->param ('debug');
    my $expires = time + $WebKDC::Config::RATE_LIMIT_INTERVAL;
    my $count = $self->{memcache}->get ("fail:$username");
    if (!defined $count) {
        $count = 0;
    }
    $count++;
    $self->{memcache}->set ("fail:$username", $count, $expires);
}

##############################################################################
# KDC interactions
##############################################################################

# Set up all parameters to the WebKDC request, including tokens, username
# and password, proxy tokens, logging information, and REMOTE_USER
# information.  Takes a hash of cookies.
sub setup_kdc_request {
    my ($self, %cart) = @_;
    my $status = WK_SUCCESS;
    my $q      = $self->query;

    # Set up the parameters to the WebKDC request.
    $self->{request}->service_token ($self->fix_token (scalar $q->param ('ST')))
        if $q->param ('ST');
    $self->{request}->request_token ($self->fix_token (scalar $q->param ('RT')))
        if $q->param ('RT');
    $self->{request}->pass (scalar $q->param ('password'))
        if $q->param ('password');
    $self->{request}->otp (scalar $q->param ('otp'))
        if $q->param ('otp');
    $self->{request}->device_id (scalar $q->param ('device_id'))
        if $q->param ('device_id');
    $self->{request}->otp_type (scalar $q->param ('factor_type'))
        if $q->param ('factor_type');
    $self->{request}->authz_subject (scalar $q->param ('authz_subject'))
        if $q->param ('authz_subject');
    $self->{request}->login_state (scalar $q->param ('LS'))
        if $q->param ('LS');

    # For the initial login page and password change page, we may need to map
    # the username.  For OTP, we've already done this, so we don't need to do
    # it again.
    if ($q->param ('password') && $q->param ('username')) {
        my $username = $q->param ('username');
        if (defined (&WebKDC::Config::map_username)) {
            $username = WebKDC::Config::map_username ($username);
        }
        if (defined $username) {
            if ($WebKDC::Config::DEFAULT_REALM && $username !~ /\@/) {
                $username .= '@' . $WebKDC::Config::DEFAULT_REALM;
            }
        } else {
            $username = '';
            $status = WK_ERR_LOGIN_FAILED;
        }
        $q->param ('username', $username);
    }
    $self->{request}->user (scalar $q->param ('username')) if $q->param ('username');

    # Check for replays or rate limiting of failed authentications for the
    # initial login page, the multifactor login page, and the multifactor_send
    # page.
    if ($q->param ('username')
          && ($q->param ('password') || $q->param ('otp')
              || ($q->param ('rm')
                  && $q->param ('rm') eq 'multifactor_sendauth'))) {
        my $username = $q->param ('username');

        # Check for replay.  The request token won't exist if we're processing
        # a password change instead of an authentication.
        if ($self->{request}->request_token) {
            if ($self->is_replay ($self->{request}->request_token)) {
                $status = WK_ERR_AUTH_REPLAY;
            }
        }

        # Check for rate limiting.  This applies to password changes as well
        # as authentications, since the password change screen could still be
        # used to guess the user's password otherwise.
        if ($self->is_rate_limited ($username)) {
            $status = WK_ERR_AUTH_LOCKOUT;
        }
    }

    # Also pass to the WebKDC any proxy tokens we have from cookies.
    # Enumerate all cookies that start with webauth_wpt (WebAuth Proxy Token)
    # and stuff them into the WebKDC request.
    my $wpt_cookie;
    for my $type (keys %cart) {
        next if not defined $q->cookie ($type);
        next if $q->cookie ($type) eq $EXPIRED_COOKIE;

        if ($type =~ /^webauth_wpt/) {
            my $short_type = $type;
            $short_type=~ s/^webauth_wpt_//;
            $self->{request}->proxy_cookie ($short_type, $q->cookie ($type),
                                            'c');
            print STDERR "found a cookie of type $type\n"
                if $self->param ('debug');
            $wpt_cookie = 1;
        } elsif ($type eq 'webauth_wft') {
            $self->{request}->factor_token ($q->cookie ($type));
        }
    }
    $self->param ('wpt_cookie', $wpt_cookie);

    # Pass in the network connection information.  This is only used for
    # additional logging in the WebKDC.
    $self->{request}->local_ip_addr ($ENV{SERVER_ADDR});
    $self->{request}->local_ip_port ($ENV{SERVER_PORT});
    $self->{request}->remote_ip_addr ($ENV{REMOTE_ADDR});
    $self->{request}->remote_ip_port ($ENV{REMOTE_PORT});

    # The WebKDC doesn't use this yet, but we might like to in the future.
    $self->{request}->remote_user ($ENV{REMOTE_USER});

    # If there is an authenticate callback defined, call it.  On failure, it
    # will return an empty list; on success, it will return a list of four
    # values: the authenticated identity, the initial factors, the session
    # factors, and the LoA.
    my $remuser_done;
    if (defined &WebKDC::Config::authenticate) {
        my ($id, $initial, $session, $loa) = WebKDC::Config::authenticate ();
        if (defined $loa) {
            my $args = {
                subject         => $id,
                initial_factors => $initial,
                session_factors => $session,
                loa             => $loa,
            };
            $self->add_generic_proxy_token ($args);
            $remuser_done = 1;
        }
    }

    # Provided that authenticate hasn't already done work, if
    # WebKDC::Config::REMUSER_ENABLED is set to a true value, see if we have a
    # ticket cache.  If so, obtain a proxy token in advance.  Otherwise,
    # cobble up a proxy token using the value of REMOTE_USER and add it to the
    # request.  This allows the WebKDC to trust Apache authentication
    # mechanisms like SPNEGO or client-side certificates if so configured.
    if (!$remuser_done) {
        if ($ENV{REMOTE_USER} && $WebKDC::Config::REMUSER_ENABLED) {
            if ($ENV{KRB5CCNAME} && $WebKDC::Config::WEBKDC_PRINCIPAL) {
                $self->add_kerberos_proxy_token;
            } else {
                $self->add_remuser_token;
            }
        }
    }
    return $status;
}

# Handle errors from the login process.  This code is shared between the login
# screen and the resubmission of the confirmation screen when the
# authorization identity was changed.
#
# Call this method with the status and the error message (if any).  The return
# value will be the page to display, which means that the caller can just
# return the return value of this method.
sub handle_login_error {
    my ($self, $status, $error) = @_;
    my $q = $self->query;
    my $req = $self->{request};
    my $resp = $self->{response};

    # WK_ERR_USER_AND_PASS_REQUIRED indicates the first visit to the login
    # page, WK_ERR_LOGIN_FAILED indicates the user needs to try logging in
    # again, and WK_ERR_LOGIN_FORCED indicates this site requires
    # username/password even if the user has other auth methods.

    # User's password has expired and we have somewhere to send them to get it
    # changed.  Get the CPT (unless we require resending the password) and
    # update the script name.
    # 1B
    if ($status == WK_ERR_CREDS_EXPIRED
        && defined ($WebKDC::Config::EXPIRING_PW_URL)) {

        if (!$WebKDC::Config::EXPIRING_PW_RESEND_PASSWORD) {
            $self->add_changepw_token;
        } else {
            $self->template_params ({skip_username => 1});
        }

        $self->param ('script_name', $WebKDC::Config::EXPIRING_PW_URL);
        $self->query->param ('expired', '1');
        return $self->print_pwchange_page ($req->request_token,
                                           $req->service_token);

    # Other authentication methods can be used, REMOTE_USER support is
    # requested by cookie, we're not already at the REMOTE_USER-authenticated
    # URL, and we're not an error handler (meaning that we haven't tried
    # REMOTE_USER and failed).  Redirect to the REMOTE_USER URL.
        # 1C - Should be doing this before actually trying the webkdc login.
        #      Shouldn't be checking for the status it's checking.
        #      Should check for cookie -- remove status check and move up in
        #         flow for initial visit.
    } elsif ($status == WK_ERR_USER_AND_PASS_REQUIRED
             && !$ENV{REMOTE_USER}
             && $q->cookie ($self->param ('remuser_cookie'))
             && !$self->param ('is_error')
             && !$q->param ('login')
             && $WebKDC::Config::REMUSER_REDIRECT) {
        print STDERR "redirecting to REMOTE_USER page\n"
            if $self->param ('debug');
        return $self->print_remuser_redirect;

    # We've tried REMOTE_USER and failed, the site has said that the user has
    # to use username/password no matter what, REMOTE_USER redirects are not
    # supported, or the user has already tried username/password.  Display the
    # login screen without the REMOTE_USER choice.
    # 1D -- Displaying traditional login screen.
    } elsif ($status == WK_ERR_USER_AND_PASS_REQUIRED
             || $status == WK_ERR_LOGIN_FORCED
             || $status == WK_ERR_LOGIN_FAILED
             || $status == WK_ERR_USER_REJECTED) {
        if ($WebKDC::Config::REMUSER_REDIRECT) {
            $self->param ('remuser_failed', $self->param ('is_error'));
        }

        if ($status == WK_ERR_USER_AND_PASS_REQUIRED
            && !$q->cookie ($self->param ('remuser_cookie'))
            && !$self->param ('is_error')) {
            $self->param ('remuser_url', $WebKDC::Config::REMUSER_REDIRECT);
        }

        # If logins were forced, we want to tell the user.  However, if this
        # is the first site they've authenticated to, we only want to tell the
        # user that if they request REMUSER support.  So, if forced login was
        # set *and* either the user has single sign-on cookies or wants to do
        # REMUSER, set the relevant template variable.
        if ($status == WK_ERR_LOGIN_FORCED
            && ($self->param ('wpt_cookie')
                     || $q->cookie ($self->param ('remuser_cookie')))) {
            $self->param ('forced_login', 1);
        }

        # If the login failed, register that for rate limiting.
        if ($status == WK_ERR_LOGIN_FAILED) {
            $self->register_auth_fail ($req->user);
        }

        print STDERR "WebKDC::make_request_token_request failed,"
            . " displaying login page\n"
            if $self->param ('debug');
        return $self->print_login_page ($status, $req->request_token,
                                        $req->service_token);

    # Multifactor was required and the KDC says the user can give it.  If the
    # WebKDC knows who the user is, always use the authenticated identity from
    # the WebKDC, rather than whatever the user typed, since we may have done
    # Kerberos canonicalization during the authentication.
    } elsif ($status == WK_ERR_MULTIFACTOR_REQUIRED) {
        print STDERR "multifactor required for login\n"
            if $self->param ('debug');

        my $req = $self->{request};
        if (defined $resp->subject) {
            $q->param ('username', $resp->subject);
        }
        return $self->print_multifactor_page ($req->request_token,
                                              $req->service_token);

    # Multifactor was required but they have no or insufficiently high
    # multifactor configured.
    } elsif ($status == WK_ERR_MULTIFACTOR_UNAVAILABLE) {
        my $mf_setup = 0;
        foreach my $factor (@{$resp->factor_configured}) {
            $mf_setup = 1 if $factor eq 'm';
        }
        if ($mf_setup) {
            $self->template_params ({err_insufficient_mfactor => 1});
            $self->template_params ({multifactor_configured
                        => $resp->factor_configured });
            $self->template_params ({multifactor_required
                        => $resp->factor_needed });
        } else {
            $self->template_params ({err_no_mfactor => 1});
        }
        return $self->print_error_page;

    # Multifactor was configured, but at too low a level of assurance to
    # satisfy the destination site.
    } elsif ($status == WK_ERR_LOA_UNAVAILABLE) {
        $self->template_params ({err_insufficient_loa => 1});
        return $self->print_error_page;

    # The authentication was rejected, probably by the user information
    # service.  We may have a custom error message from the WebKDC and
    # therefore a custom error page to display to the user.
    } elsif ($status == WK_ERR_AUTH_REJECTED
             || $status == WK_ERR_LOGIN_REJECTED) {
        if ($error->data) {
            $self->template_params ({err_html => $error->data});
        } else {
            $self->template_params ({err_webkdc => 1});
            $self->template_params ({err_msg => 'authentication rejected.'});
        }
        return $self->print_error_page;

    # Request was a replay.  Users are only allowed to do a username and
    # password authentication with a given request token once, since otherwise
    # someone may use the back button in an abandoned browser to log in again.
    } elsif ($status == WK_ERR_AUTH_REPLAY) {
        $self->template_params ({err_replay => 1});
        return $self->print_error_page;

    # User reached the rate limit of failed logins.
    } elsif ($status == WK_ERR_AUTH_LOCKOUT) {
        $self->template_params ({err_lockout => 1});
        return $self->print_error_page;

    # Something abnormal happened.  Figure out what error message to display
    # and throw up the error page instead.
    } else {
        my $errmsg = '';

        # Something very nasty.  Just display a "we don't know" error.
        if ($status == WK_ERR_UNRECOVERABLE_ERROR) {
            $errmsg = "unrecoverable error occured. Try again later.";

        # User took too long to login and the original request token is stale.
        } elsif ($status == WK_ERR_REQUEST_TOKEN_STALE) {
            $errmsg = "you took too long to login.";

        # User's password has expired and we don't have anywhere to send them
        # to change it.
        } elsif ($status == WK_ERR_CREDS_EXPIRED) {
            $errmsg = "your password has expired.";

        # Like WK_ERR_UNRECOVERABLE_ERROR, but indicates the error most likely
        # is due to the webauth server making the request, so stop but display
        # a different error messaage.
        } elsif ($status == WK_ERR_WEBAUTH_SERVER_ERROR) {
            $errmsg = "there is most likely a configuration problem with"
                . " the server that redirected you. Please contact its"
                . " administrator.";
        }

        # Display the error page.
        print STDERR "WebKDC::make_request_token_request failed with"
            . " $errmsg: $error\n" if $self->param ('logging');
        $self->template_params ({err_webkdc => 1});
        $self->template_params ({err_msg => $errmsg});
        return $self->print_error_page;
    }
}

##############################################################################
# Actions to various requests
##############################################################################

# Main index, to log users in or display the login page if they are required
# to enter login data.
# Pages: multifactor page (success + multifactor required)
#        login page (login failure)
#        password reset page (success + password expired)
#        confirm page (success + no multifactor + confirm required)
#        redirect to base site (success + no multifactor + no confirm)
#        error page (some critical failure)
#        internal service error page (could not call template)
sub index : StartRunmode {
    my ($self) = @_;

    my $q = $self->query;
    my $req = $self->{request};
    my $resp = $self->{response};
    my ($status, $error);

    # Test for lack of a request token, cookies not being enabled, or
    # sending passwords over a non-POST method.  If found, these will
    # internally handle the error pages, so we stop processing this
    # request.
    my $page;
    return $page if defined ($page = $self->error_no_request_token);
    return $page if defined ($page = $self->error_if_no_cookies);
    return $page if defined ($page = $self->error_password_no_post);

    # Set up all WebKDC parameters, including tokens, proxy tokens, and
    # IP and trace information.
    my %cart = CGI::Cookie->fetch;
    $status = $self->setup_kdc_request (%cart);

    # Pass the information along to the WebKDC and get the response.
    if (!$status) {
        ($status, $error) = WebKDC::make_request_token_request ($req, $resp);
    }

    # Parse the result from the WebKDC and get the login cancel information if
    # any.
    # FIXME: (The login cancel stuff is oddly placed here, like it was added
    # as an afterthought, and should probably be handled in a cleaner
    # fashion.)
    $self->get_login_cancel_url;

    # parse_uri returns 1 on failure to parse the return_url.
    if ($status == WK_SUCCESS && $self->parse_uri) {
        $status = WK_ERR_WEBAUTH_SERVER_ERROR;
    }

    # Now, display the appropriate page.  If $status is WK_SUCCESS, we have a
    # successful authentication (by way of proxy token or username/password
    # login).  Otherwise, process the error.
    # Auth branch on "WebKDC return status" 1A
    if ($status == WK_SUCCESS) {
        if (defined (&WebKDC::Config::record_login)) {
            WebKDC::Config::record_login ($resp->subject);
        }
        if ($q->param ('password')) {
            $self->register_auth ($req->request_token, $resp->subject);
        }

        print STDERR "WebKDC::make_request_token_request success\n"
            if $self->param ('debug');
        return $self->print_confirm_page;
    } else {
        return $self->handle_login_error ($status, $error);
    }
}

# Process a request to log out of the page.  This won't be called by anything
# else by WebLogin, only by the logout page directly.
# Pages: logout template (success)
#        service error page (failure building template)
sub logout : Runmode {
    my ($self) = @_;
    my $q = $self->query;
    my %cookies = CGI::Cookie->fetch;
    my $ca;
    my %params;

    # Locate any webauth_wpt cookies and blow them away, by setting the same
    # cookie again with a null value and an expiration date in the past.
    for my $key (sort keys %cookies) {
        if ($key =~ /^webauth_wpt/) {
            my ($name) = split ('=', $cookies{$key});
            push (@$ca, $q->cookie (-name => $name, -value => $EXPIRED_COOKIE,
                                    -expires => '-1d', -secure => 1));
         }
    }

    $self->header_props (-type => 'text/html', -Pragma => 'no-cache',
                         -Cache_Control => 'no-cache, no-store');
    if ($ca) {
        $params{cookies_flag} = 1;
        $self->header_add (-cookie => $ca);
    }

    my $pages = $self->param ('pages');
    my $pagename = $pages->{logout};
    my $content = $self->tt_process ($pagename, \%params);
    if ($content) {
        return $content;
    } else {
        return $self->print_error_fatal ('could not process login template');
    }
}

# Handle the user attempting to change current password, whether from the
# user's own request or a force-change on password expiration.
# Pages: password change screen (failure)
#        login screen (success on force-change)
#        confirm page (success on user deciding to change)
sub pwchange : Runmode {
    my ($self) = @_;

    # Set up all WebKDC parameters, including tokens, proxy tokens, and
    # REMOTE_USER parameters.
    my %cart = CGI::Cookie->fetch;
    my $status = $self->setup_kdc_request (%cart);

    my $q = $self->query;
    my $req = $self->{request};
    my $resp = $self->{response};

    # Cases we might encounter:
    # * Expired password -- login.fcgi creates a changepw cred token and
    #   sends us here.
    # * Password going to expire soon -- login.fcgi creates a changpw cred
    #   token and gives a button to send us here.
    # * User choice -- User comes here on their own, needing to enter username
    #   and password

    # Check to see if this is our first visit and simply show the change page
    # if so (skipping checks for missing fields).
    if (!$self->query->param ('changepw')) {
        return $self->print_pwchange_page ($req->request_token,
                                           $req->service_token);
    }

    # Test to make sure that all required fields are filled out.
    my $page;
    return $page if defined ($page = $self->error_invalid_pwchange_fields);
    return $page if defined ($page = $self->error_if_no_cookies);
    return $page if defined ($page = $self->error_password_no_post);

    # Attempt password change via krb5_change_password API.
    my $error = '';
    if ($status == WK_SUCCESS) {
        ($status, $error) = $self->change_user_password;
    }

    # We've successfully changed the password.  Depending on if we were sent
    # by an expired password, either pass along to the normal page or give a
    # confirm screen.
    if ($status == WK_SUCCESS) {

        # Expired password -- drop back into the normal process flow.
        # 2A
        if ($self->query->param ('expired')
            and $self->query->param ('expired') == 1) {

            # Get the right script name and password.
            $self->param ('script_name', $WebKDC::Config::LOGIN_URL);
            my $newpass = $self->query->param ('new_passwd1');
            $self->query->param ('password', $newpass);

            # Move back into the main page flow now.
            return $self->forward ('index');

        # We weren't sent by expired password -- just print a confirm.
        # 2B
        } else {
            return $self->print_pwchange_confirm_page;
        }

    # Check if the user's old password was wrong.
    } elsif ($status == WK_ERR_LOGIN_FAILED) {
        $self->template_params ({error => 1});
        $self->template_params ({err_loginfailed => 1});
        return $self->print_pwchange_page ($self->query->param ('RT'),
                                           $self->query->param ('ST'));

    # The password change failed for some reason.  Display the password change
    # page again, with the error template variable filled in.  Heimdal, when
    # using an external password strength checking program, adds a prefix to
    # the error message that users don't care about, so strip that out.
    } else {
        $error =~ s/^Kerberos error \((.*)\)/$1/;
        $error =~ s/^password change failed for \S+: \(\d+\) //;
        $error =~ s/External password quality program failed: //;
        $self->template_params ({error => 1});
        $self->template_params ({err_pwchange => 1});
        $self->template_params ({err_msg => $error});
        return $self->print_pwchange_page ($self->query->param ('RT'),
                                           $self->query->param ('ST'));
    }
}

# Handle displaying the password change screen when the user has explicitly
# requested that screen.  This variation will not be called by anything else
# in the pages, only by the pwchange script directly.
# Pages: password change screen (success)
sub pwchange_display : Runmode {
    my ($self) = @_;

    # Set up all WebKDC parameters, including tokens, proxy tokens, and
    # REMOTE_USER parameters.
    my %cart = CGI::Cookie->fetch;
    $self->setup_kdc_request (%cart);

    my $req = $self->{request};
    my $resp = $self->{response};
    return $self->print_pwchange_page ($req->request_token,
                                       $req->service_token);
}

# Handle a multifactor login request, or request to send an SMS for
# multifactor login.
# Pages: Multifactor page (failure to login or sending an SMS)
#        Passes to normal login process (success)
sub multifactor : Runmode {
    my ($self) = @_;
    my $q = $self->query;

    # The username should always be set here.
    if (!defined ($q->param ('username'))) {
        $self->template_params ({err_confirm => 1});
        return $self->print_error_page;
    }

    # Set up all WebKDC parameters, including tokens, proxy tokens, and
    # REMOTE_USER parameters.
    my %cart = CGI::Cookie->fetch;
    my $status = $self->setup_kdc_request (%cart);

    # Either we have a non-OTP factor type, or the OTP is set.
    if (defined $q->param('otp') && $q->param('otp') ne '') {
        my $req = $self->{request};
        my $resp = $self->{response};
        $req->user ($q->param ('username'));
        my $error;
        if ($status == 0) {
            ($status, $error)
                = WebKDC::make_request_token_request ($req, $resp);
        }

        if ($status == WK_SUCCESS) {
            print STDERR "WebKDC::make_request_token_request success\n"
                if $self->param ('debug');
            $self->register_auth ($req->request_token, $resp->subject);
            return $self->print_confirm_page;
        } elsif ($status == WK_ERR_MULTIFACTOR_REQUIRED) {
            print STDERR "additional multifactor required\n"
                if $self->param ('logging');
        } elsif ($status == WK_ERR_LOGIN_FAILED) {
            print STDERR "multifactor failed: $error ($status)\n"
                if $self->param ('logging');
            $self->template_params ({err_multifactor_invalid => 1});
            $self->register_auth_fail ($req->user);
        } elsif ($status == WK_ERR_LOGIN_REJECTED) {
            my $message = $resp->user_message;
            print STDERR "multifactor rejected: $error ($status): $message\n"
                if $self->param ('logging');
            $self->register_auth_fail ($req->user);
        } elsif ($status == WK_ERR_LOGIN_TIMEOUT) {
            print STDERR "multifactor timeout: $error ($status)\n"
                if $self->param ('logging');
            $self->template_params ({err_multifactor_timeout => 1});

        } else {
            # Hopefully this is close enough that we can just use the default
            # error handling code.
            return $self->handle_login_error ($status, $error);
        }
    } else {
        $self->template_params ({err_multifactor_missing => 1});
    }

    if ($q->param ('multifactor_sentauth')) {
        $self->template_params ({multifactor_sentauth => 1});
    }
    my $req = $self->{request};
    return $self->print_multifactor_page ($req->request_token,
                                          $req->service_token);
}

# Handle a request to send a multifactor authentication token somewhere via
# program.  The normal example case would be to fire off a command that sends
# an OTP via SMS.
# Pages: Multifactor page on success
#        Error page on any failure
sub multifactor_sendauth : Runmode {
    my ($self) = @_;
    my $q = $self->query;

    # The username should always be set here.
    if (!defined ($q->param ('username'))) {
        $self->template_params ({err_confirm => 1});
        return $self->print_error_page;
    }

    # Set up all WebKDC parameters, including tokens, proxy tokens, and
    # REMOTE_USER parameters.
    my %cart = CGI::Cookie->fetch;
    my $status = $self->setup_kdc_request (%cart);

    # Check for replays and authentication rate limiting
    if ($status == WK_ERR_AUTH_REPLAY) {
        $self->template_params ({err_replay => 1});
        return $self->print_error_page;
    } elsif ($status == WK_ERR_AUTH_LOCKOUT) {
        $self->template_params ({err_lockout => 1});
        return $self->print_error_page;
    }

    # Error if we don't have the setup configured.
    if (!$WebKDC::Config::MULTIFACTOR_SERVER
        || !$WebKDC::Config::MULTIFACTOR_COMMAND) {

        print STDERR "multifactor_sendauth failed due to no server "
            . "configured\n" if $self->param ('logging');

        my $errmsg = "unrecoverable error occured. Try again later.";
        $self->template_params ({err_webkdc => 1});
        $self->template_params ({err_msg => $errmsg});
        return $self->print_error_page;

    } else {

        # Send the remctl command, switching tgts out beforehand.
        my $username = $q->param ('username');
        my $device   = $q->param ('device_id');
        my @cmd = split (' ', $WebKDC::Config::MULTIFACTOR_COMMAND);
        local $ENV{KRB5CCNAME} = $WebKDC::Config::MULTIFACTOR_TGT;
        my $result = Net::Remctl::remctl ($WebKDC::Config::MULTIFACTOR_SERVER,
                                          $WebKDC::Config::MULTIFACTOR_PORT,
                                          $WebKDC::Config::MULTIFACTOR_PRINC,
                                          @cmd, $username, $device);

        if ($result->error) {
            print STDERR "multifactor_sendauth failed to run program: " .
                $result->error . "\n" if $self->param ('logging');
            $self->template_params ({err_sendauth => 1});
            return $self->print_error_page;
        } elsif ($result->status != 0) {
            print STDERR "multifactor_sendauth failed to run program: " .
                $result->stderr . "\n" if $self->param ('logging');
            $self->template_params ({err_sendauth => 1});
            return $self->print_error_page;
        } else {
            $self->template_params ({multifactor_sentauth => 1});
            my $req = $self->{request};
            return $self->print_multifactor_page ($req->request_token,
                                                  $req->service_token);
        }
    }
}

# Handle the request from the user to change the authorization identity,
# called from the confirm screen.  For this case, we'll need to resubmit the
# authentication request and get a new id or proxy token.
# Pages: confirm screen
sub edit_authz_identity : Runmode {
    my ($self) = @_;

    # Set up all WebKDC parameters, including tokens, proxy tokens, and
    # REMOTE_USER parameters.
    my %cart = CGI::Cookie->fetch;
    my $status = $self->setup_kdc_request (%cart);

    # Resubmit the authentication request.
    my $req = $self->{request};
    my $resp = $self->{response};
    my $error;
    if ($status == 0) {
        ($status, $error) = WebKDC::make_request_token_request ($req, $resp);
    }
    if ($status == WK_SUCCESS) {
        print STDERR "WebKDC::make_request_token_request success\n"
            if $self->param ('debug');
        return $self->print_confirm_page;
    } else {
        return $self->handle_login_error ($status, $error);
    }
}

# Handle the request from the user to change their REMOTE_USER setting, called
# from the confirm screen.  All of the actual 'action' here is performed by
# the confirm screen sending itself with a cookie set or cleared.
# Pages: confirm screen
sub edit_remoteuser : Runmode {
    my ($self) = @_;

    # Set up all WebKDC parameters, including tokens, proxy tokens, and
    # REMOTE_USER parameters.
    my %cart = CGI::Cookie->fetch;
    $self->setup_kdc_request (%cart);

    my $q = $self->query;
    return $self->redisplay_confirm_page;
}

##############################################################################
# Documentation
##############################################################################

1;

__END__

=for stopwords
WebAuth WebLogin CGI login API Allbery CPT FastCGI PAGETYPE SMS SPNEGO SSL
URI USERNAME login logins memcached redisplay remctl username keyring
post-login logout OTP WebKDC multifactor

=head1 NAME

WebLogin - Central login service for the WebAuth authentication system

=head1 SYNOPSIS

    use WebLogin;

    my $weblogin = WebLogin->new (PARAMS => { pages => \%pages },
                                  QUERY  => $q);
    $weblogin->run;

=head1 DESCRIPTION

The WebLogin module implements a CGI service using the CGI::Application
framework that provides central login services for the WebAuth
authentication system.  For its entry points and constructor options, see
L<CGI::Application/"Instance Script Methods">.

This module is normally only called from the F<login.fcgi>, F<logout.fcgi>,
and F<pwchange.cgi> scripts that come with WebAuth and comprise, with this
module, the WebLogin service.  It is not currently designed to be used by
any other scripts and does not currently have a documented API.

=head1 FUNCTIONS

=over 4

=item setup

Overridden CGI::Application setup function.  This is used for all
initialization of data needed for our WebLogin object.  It sets various
defaults, sets up our Template Toolkit options, creates memcached
caches, and other needed setup items to prepare.

=item cgiapp_prerun

Overridden CGI::Application function that is called before the
processing of each individual query.  This does further setup that's
meant to be query-specific, since we're potentially being wrapped up in
FastCGI or other methods that will cache the WebLogin object.

This includes clearing any parameters or template parameters from
previous runs, creating fresh objects for handling current query and
responses, and storing other query-specific data.

=item krb5_escape (PRINCIPAL)

Escape special characters in a principal name to match the escaping done
by krb5_unparse_name.  Returns the escaped principal name.

=item fix_token (TOKEN)

Encode a token for URL usage.

=item expire_cookie (NAME, SECURE)

Create and return a CGI::Cookie object that will expire an existing
cookie.  The cookie has the given NAME set, and includes the given flag
as to whether or not it uses SSL.

=item is_factor_set

Uses the cookies set on the WebKDC::WebResponse object to determine if
we have a factor token passed back from the WebKDC.  Returns 1 if so, 0
if not.

=item template_params (SETTINGS_REF)

Interface used to wrap up and save various parameters that we are
storing to later be used in the template files.  Takes a hashref to
settings we wish to add/override, and returns the ending hashref of all
current parameters.

=item get_pagename (PAGETYPE)

Takes the type of page we want, then returns the file name of the
template that is used to display that page type.

=item print_headers (ARGS_REF)

Sets the headers for a page.  This handles setting or removing any
cookies, then setting the headers.  If a return URL was set, add a
redirect to that URL into the headers.

=item pretty_return_uri (URI)

Takes a URI object and uses it to create a 'pretty' return URI, one
that's more readable by users for display on the configuration page.
Returns a string containing that URI.

=item parse_uri

Parses the return URL from the web response and either sets the pretty
URI (via petty_return_uri) or flags an error to the template if there
was something wrong with the URL.

=item token_rights

Parses the F<token.acl> file, using that to return an arrayref of the
credentials that the requesting WAS is permitted to obtain.  This is
used in cases where a specific WAS might have access to request
delegated credentials.

=item get_login_cancel_url

Checks to see if there is a login canceled token, and if so, sets
template parameters to offer a login canceled URL with that token.

=item print_login_page

View for the user login page.  This is the view that allows a user to
attempt to login, offering fields for username and password, possibly a
URL for remote user authentication, and any errors from previous failed
logins.

=item print_error_page

View for the generic error page.  This will pass along any previously
set error types for the template, and make sure that the error page
itself isn't cached.

=item print_error_fatal

View for a fatal error.  This is something normally only used on an
error to print out a template, meant as an emergency fallback to
display something when things are very messed up.

=item print_confirm_page

View for the confirmation page post-login.  This potentially includes a
password expiration warning, a warning for expiring device factor
cookies, and a notice for delegated credentials.  If none of those are
set, then we may (on WebKDC::Config settings) bypass the confirmation
page entirely and just send a redirect to the login destination.

=item redisplay_confirm_page

View to redisplay the confirmation page after a change in the
REMOTE_USER cookie.  This is a much more simple version of
print_confirm_page, as it doesn't have to do most of the checking for
warnings and whether or not to bypass the page.

=item print_pwchange_page

View to print out the password change page.  Pass along any needed user
information, such as their login information and any change password
token.

=item print_pwchange_confirm_page

View to print out a confirmation after a successful password change.
This is only accessed when the user is going to the password change
page via the URL just for that, rather than as a part of the normal
login flow.

=item print_multifactor_page

View to print out a page prompting the user to enter their multifactor
one-time password.  We pass along user information, the factors
needed for login, and the factors the user has.

=item print_remuser_redirect

Redirect a user to the REMOTE_USER enabled login URL.  This passes the
request token and service token on to the URL, then returns it as a
redirect page for CGI::Application to print.

=item add_generic_proxy_token (ARGS_REFERENCE)

Create and add a generic token to the set of tokens passed to the
WebKDC via the web request.  Read the ARGS_REFERENCE for any
non-default arguments we wish to create the proxy token with, then
create a new WebAuth::Token::WebKDCProxy object.  Encode it with the
keyring and add it to the proxy cookies on the web request.

=item add_kerberos_proxy_token

Create a proxy token using forwarded Kerberos credentials and pass into
the web request.

=item add_remuser_token

Create a proxy token with the REMOTE_USER identity and pass into the
web request.  This does validation against the REMOTE_USER setting,
then passes along to add_generic_proxy_token if it passes our
requirements.

=item add_changepw_token

Create a kadmin/changepw token using the username and password of a
user after successful login.  This will create a ticket, put it into a
WebAuth::Token::Cred object, and use the keyring to encode it.  The
token is passed back as the CPT parameter on the WebLogin object.
Returns 1 on success.

=item change_user_password

Attempt to change a user's password using a previously created change
password token.  Validate that the token is correct for the given user,
then attempt to change the user's password, returning a status and any
exception objects that may have been created during failures.

=item error_if_no_cookies

Tests to make sure that cookies are enabled in the user's browser.  If
a test cookie is not set, we reload the page with an attempt to set
that cookie and a flag showing that we're making the attempt.  If we
find the flag set and no cookie, then the user does not have cookies
set, and we display an error page.

=item error_password_no_post

Tests to make sure that if a password was sent, the request method was
POST.  This is done in order to avoid the password potentially showing
up in referrer strings sent to a remote site.  If the method was not
POST, we display an error page.

=item error_no_request_token

Tests to make sure that we have a request token and service token
defined in the submitted CGI query.  If not, we will display an error
page.

=item error_invalid_pwchange_fields

Tests the requirements for a password change request page to be
successfully entered.  This does not actually try to change the
password or check that it is successful, but only checks to make sure
that the user has entered all of the needed data.  If not, we will
display the password change page again, with error flags for the
missing or incorrect fields.

=item is_replay (RT)

Checks against memcached to see if the given request token has been
recently used, in order to detect a replay attack.  Returns 1 if the
request token was found.

=item is_rate_limited (USERNAME)

Checks against memcached to see if the given user has exceeded a
certain number of failed logins.  Returns 1 if the user has exceeded
the number (set in WebKDC::Config).

=item register_auth (RT, USERNAME)

Registers a successful authentication for the given user in memcached,
with the request token for the authentication.  This is used to detect
replay attacks.

=item register_auth_fail (USERNAME)

Registers a failed authentication for the given user in memcached.  This
is used for rate limiting users on failed logins.

=item setup_kdc_request (COOKIES)

Takes the WebKDC::WebRequest object already created, and fills that
object with data from the user/browser.  This includes current cookies
passed to us, and also any relevant data sent via the CGI query.  The
latter can include username and password, for two examples.

Returns the status from the request.  This is usually WK_SUCCESS as we
are not actually contacting the WebKDC at this point, but can be error
statuses in cases such as the user not filling in their username, or
if replay or rate limited checks were triggered.

=item handle_login_error (STATUS, ERROR)

This is a catch-all handler for any error during the normal user login
process.  This uses the given error status to decide what needs to be
done to handle this error case, often simply printing out a screen to
request additional information or the user to re-enter correct
information.  In some cases, this will have to throw up an
unrecoverable error page that the user can do nothing with.

=item index

The default run mode, handling the basic attempt to log in, whether via
plain username and password, SPNEGO, or other method.

This is called if no other run mode is set by the main login URL, or on
any regular failure to successfully log in (such as invalid password).

=item logout

Run mode to handle a request by the user to log out, blowing away all
proxy cookies.

This is only called via the logout URL.

=item pwchange()

Run mode to handle an attempt by the user to change their current
password.  This handles the attempt to change the user password, either
passing the user on to the confirmation page or bringing the user back
to this page on a problem with changing the password.

This is called by either the user clicking a link from the confirm page
warning that their password is soon to expire, or by the user being
forced to here after logging in with an expired password.

=item pwchange_display

Run mode to handle a direct access to the password change display
screen.

This is called only by the user visiting the password change URL from
outside the normal program flow.

=item multifactor

Run mode to handle an attempted multifactor login.  The username and
one-time password are passed to the WebKDC in order to validate whether or
not there was a successful login, and the user is then sent to either the
confirm page on success, or the multifactor page again on failure.

This is called from the multifactor entry screen, when the user submits
their one-time password.

=item multifactor_sendauth

Run mode to handle the request from a user to send a multifactor
authentication token somewhere via a remctl command.  The command
itself is configured in WebKDC::Config.  The normal case would be
sending out a OTP over SMS to a user.

This is called from the multifactor entry screen, in the case of a user
having a multifactor method that requires the user be sent a token.

=item edit_authz_identity

Run mode to handle the request from a user to change their authorization
identity.

This is called from the config screen.

=item edit_remoteuser

Run mode to handle the request from a user to change their REMOTE_USER
setting.

This is called from the config screen.

=back

=head1 AUTHORS

Roland Schemers, Russ Allbery <eagle@eyrie.org>, and Jon Robertson
<jonrober@stanford.edu>.

=head1 SEE ALSO

WebAuth(3), WebKDC(3), WebKDC::Config(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
