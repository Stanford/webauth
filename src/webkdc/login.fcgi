#!/usr/bin/perl -w
our $ID = q($Id$ );
#
# login.fcgi -- Weblogin login page for WebAuth.
#
# Written by Roland Schemers <schemers@stanford.edu>
# Copyright 2002, 2003, 2004, 2005, 2006
#     Board of Trustees, Leland Stanford Jr. University
#
# This is the front page for user authentication for weblogin.  It accepts
# information from the user, passes it to the WebKDC for authentication, sets
# appropriate cookies, and displays the confirmation page and return links.
#
# It should use FastCGI if available, using the Perl CGI::Fast module's
# ability to fall back on regular operation if FastCGI isn't available.

##############################################################################
# Modules and declarations
##############################################################################

require 5.006;

use strict;

use CGI ();
use CGI::Cookie ();
use CGI::Fast ();
use HTML::Template ();
use WebAuth qw(:base64 :const :krb5 :key);
use WebKDC ();
use WebKDC::Config ();
use WebKDC::WebKDCException;
use URI ();
use URI::Escape qw(uri_unescape);

# Set to true in order to enable debugging output.  This will be very chatty
# in the logs and may log security-sensitive tokens and other information.
our $DEBUG = 0;

# Set to true to log interesting error messages to stderr.
our $LOGGING = 1;

# The names of the template pages that we use.  The beginning of the main
# routine changes the values here to be HTML::Template objects.
our %PAGES = (login   => 'login.tmpl',
              confirm => 'confirm.tmpl',
              error   => 'error.tmpl');

# The name of the cookie we set to ensure that the browser can handle cookies.
our $TEST_COOKIE = "WebloginTestCookie";

# The name of the cookie holding REMOTE_USER configuration information.
our $REMUSER_COOKIE = 'weblogin_remuser';

# The lifetime of the REMOTE_USER configuration cookie.
our $REMUSER_LIFETIME = '+365d';

##############################################################################
# Debugging
##############################################################################

# Dump as much information as possible about the environment and input to
# standard output.  Not currently used anywhere, just left in here for use
# with debugging.
sub dump_stuff {
    my ($var, $val);
    foreach $var (sort keys %ENV) {
        $val = $ENV{$var};
        $val =~ s|\n|\\n|g;
        $val =~ s|\"|\\\"|g;
        print "${var}=\"${val}\"\n";
    }
    print "\n";
    print "\n";
    local $_;
    print "INPUT: $_" while <STDIN>;
}

##############################################################################
# Output
##############################################################################

# Print the headers for a page.  Takes the user's query and any additional
# cookies to set as parameters, and always adds the test cookie.  Skip any
# remuser proxy tokens, since those are internal and we want to reauthenticate
# the user every time.
sub print_headers {
    my ($q, $cookies) = @_;
    my $ca;

    # $REMUSER_COOKIE is handled as a special case, since it stores user
    # preferences and should be retained rather than being only a session
    # cookie.
    my $secure = (defined ($ENV{HTTPS}) && $ENV{HTTPS} eq 'on') ? 1 : 0;
    my $saw_remuser;
    if ($cookies) {
        my ($name, $value);
        while (($name, $value) = each %$cookies) {
            next if $name eq 'webauth_wpt_remuser';
            my $cookie;
            if ($name eq $REMUSER_COOKIE) {
                $cookie = $q->cookie(-name => $name, -value => $value,
                                     -secure => $secure,
                                     -expires => $REMUSER_LIFETIME);
                $saw_remuser = 1;
            } else {
                $cookie = $q->cookie(-name => $name, -value => $value,
                                     -secure => $secure);
            }
            push (@$ca, $cookie);
        }
    }

    # If we're not setting the $REMUSER_COOKIE cookie explicitly and it was
    # set in the query, set it in our page.  This refreshes the expiration
    # time of the cookie so that, provided the user visits WebLogin at least
    # once a year, the cookie will never expire.
    if (!$saw_remuser && $q->cookie ($REMUSER_COOKIE)) {
        my $cookie = $q->cookie (-name => $REMUSER_COOKIE, -value => 1,
                                 -secure => $secure,
                                 -expires => $REMUSER_LIFETIME);
        push (@$ca, $cookie);
    }

    # Set the test cookie unless it's already set.
    unless ($q->cookie ($TEST_COOKIE)) {
        my $cookie = $q->cookie (-name => $TEST_COOKIE, -value => 'True',
                                 -path => '/');
        push (@$ca, $cookie);
    }

    # Now, print out the page header with the appropriate cookies.
    if ($ca) {
        print $q->header (-type => 'text/html', -Pragma => 'no-cache',
                          -Cache_Control => 'no-cache, no-store',
                          -cookie => $ca);
    } else {
        print $q->header (-type => 'text/html', -Pragma => 'no-cache',
                          -Cache_Control => 'no-cache, no-store');
    }
}

# Parse the return URL of our request, filling out the provided $lvars struct
# with the details.  Make sure that the scheme exists and is a valid WebAuth
# scheme.  Return 0 if everything is okay, 1 if the scheme is invalid.
sub parse_uri {
    my ($lvars, $resp) = @_;
    my $uri = URI->new ($resp->return_url);

    $lvars->{return_url} = $uri->canonical;
    my $scheme = $uri->scheme;
    unless (defined ($scheme) && $scheme =~ /^https?$/) {
        $PAGES{error}->param (err_webkdc => 1);
        return 1;
    }
    $lvars->{scheme} = $scheme;
    $lvars->{host} = $uri->host;
    $lvars->{path} = $uri->path;
    $lvars->{port} = $uri->port if ($uri->port != 80 && $uri->port != 443);

    # Determine what pretty display URL to use.  This is a bit more
    # complicated if we're using Shibboleth; in that case, try to extract a
    # URI from the target parameter of the return URL.
    my $pretty;
    my @idps = @WebKDC::Config::SHIBBOLETH_IDPS;
    if (grep { $lvars->{host} eq $_ } @WebKDC::Config::SHIBBOLETH_IDPS) {
        my ($target) = ($uri->path =~ /\?target=([^&]+)&/);
        if ($target) {
            my $realuri = URI->new (uri_unescape ($target));
            if ($realuri && $realuri->scheme =~ /^https?$/) {
                $pretty = $realuri->scheme . "://" . $realuri->host;
            }
        }
    }
    unless ($pretty) {
        $pretty = $lvars->{scheme} . "://" . $lvars->{host};
    }
    $lvars->{pretty} = $pretty;

    return 0;
}

# Print the login page.  Takes the query, the variable hash, the error code if
# any, the WebKDC response, the request token, and the service token, and
# encodes them as appropriate in the login page.
sub print_login_page {
    my ($q, $lvars, $err, $resp, $RT, $ST) = @_;
    my $page = $PAGES{login};
    $page->param (script_name => $q->script_name);
    $page->param (username => $lvars->{username});
    $page->param (RT => $RT);
    $page->param (ST => $ST);
    $page->param (LC => $lvars->{LC});
    if ($lvars->{remuser_url}) {
        $page->param (show_remuser => 1);
        $page->param (remuser_url => $lvars->{remuser_url});
    }
    if ($lvars->{remuser_failed}) {
        $page->param (remuser_failed => 1);
    }

    # If and only if we got here as the target of a form submission (meaning
    # that they already had one shot at logging in and something didn't work),
    # set the appropriate error status.
    #
    # If they *haven't* already had one shot and forced login is set, display
    # the error box telling them they're required to log in.
    if ($q->param ('login')) {
        $page->param (err_password => 1) unless $q->param ('password');
        $page->param (err_username => 1) unless $q->param ('username');
        $page->param (err_cookies => 1) unless $q->cookie ($TEST_COOKIE);
        $page->param (err_missinginput => 1) if $page->param ('err_username');
        $page->param (err_missinginput => 1) if $page->param ('err_password');
        if ($err == WK_ERR_LOGIN_FAILED) {
            $page->param (err_loginfailed => 1);
        }

        # Set a generic error indicator if any of the specific ones were set
        # to allow easier structuring of the login page template.
        if ($page->param ('err_missinginput') || $page->param ('err_cookies')
            || $page->param ('err_loginfailed')) {
            $page->param (error => 1);
        }
    } elsif ($lvars->{forced_login}) {
        $page->param (err_forced => 1);
        $page->param (error => 1);
    }
    print_headers ($q, $resp->proxy_cookies);
    print $page->output;
}

# Print an error page, making sure that error pages are never cached.
sub print_error_page {
    my ($q) = @_;
    print $q->header (-expires => 'now');
    print $PAGES{error}->output;
}

# Encode a token.
sub fix_token {
    my ($token) = @_;
    $token =~ tr/ /+/;
    return $token;
}

# Given the query, the local variables, and the WebKDC response, print the
# login page, filling in all of the various bits of data that the page
# template needs.
sub print_confirm_page {
    my ($q, $lvars, $resp) = @_;

    my $pretty_return_url = $lvars->{pretty};
    my $return_url = $resp->return_url;
    my $lc = $resp->login_canceled_token;

    # FIXME: This looks like it generates extra, unnecessary semicolons, but
    # should be checked against the parser in the WebAuth module.
    $return_url .= "?WEBAUTHR=" . $resp->response_token . ";";
    $return_url .= ";WEBAUTHS=" . $resp->app_state . ";" if $resp->app_state;

    # Find our page and set general template parameters.
    my $page = $PAGES{confirm};
    $page->param (return_url => $return_url);
    $page->param (username => $resp->subject);
    $page->param (pretty_return_url => $pretty_return_url);

    # If there is a login cancel option, handle creating the link for it.
    if (defined $lc) {
        $page->param (login_cancel => 1);
        my $cancel_url = $resp->return_url;

        # FIXME: Looks like extra semicolons here too.
        $cancel_url .= "?WEBAUTHR=$lc;";
        $cancel_url .= ";WEBAUTHS=" . $resp->app_state . ";"
            if $resp->app_state;
        $page->param (cancel_url => $cancel_url);
    }

    # If REMOTE_USER is done at a separate URL *and* REMOTE_USER support was
    # either requested or used, show the checkbox for it.
    if ($WebKDC::Config::REMOTE_USER_REDIRECT) {
        if ($ENV{REMOTE_USER} || $q->cookie ($REMUSER_COOKIE)) {
            $page->param (show_remuser => 1);
            if ($q->cookie ($REMUSER_COOKIE)) {
                $page->param (remuser => 1);
            }
            $page->param (script_name => $q->script_name);
        }
    }

    # Print out the page, including any updated proxy cookies if needed.
    print_headers ($q, $resp->proxy_cookies);
    print $page->output;
}

# Given the query, redisplay the confirmation page after a change in the
# REMOTE_USER cookie.  Also set the new REMOTE_USER cookie.
sub redisplay_confirm_page {
    my ($q) = @_;
    my $return_url = $q->param ('return_url');
    my $username = $q->param ('username');
    my $cancel_url = $q->param ('cancel_url');

    my $uri = URI->new ($return_url);
    unless ($username && $uri && $uri->scheme && $uri->host) {
        $PAGES{error}->param (err_confirm => 1);
        print STDERR ("missing data when reconstructing confirm page\n")
            if $LOGGING;
        print_error_page ($q);
        next;
    }
    my $pretty_return_url = $uri->scheme . "://" . $uri->host;

    # Find our page and set general template parameters.
    my $page = $PAGES{confirm};
    $page->param (return_url => $return_url);
    $page->param (username => $username);
    $page->param (pretty_return_url => $pretty_return_url);
    $page->param (script_name => $q->script_name);
    $page->param (show_remuser => 1);
    my $remuser = $q->param ('remuser') eq 'on' ? 'checked' : '';
    $page->param (remuser => $remuser);

    # If there is a login cancel option, handle creating the link for it.
    if (defined $cancel_url) {
        $page->param (login_cancel => 1);
        $page->param (cancel_url => $cancel_url);
    }

    # Print out the page, including the new REMOTE_USER cookie.
    print_headers ($q, { $REMUSER_COOKIE => ($remuser ? 1 : 0) });
    print $page->output;
}

# Obtains the login cancel URL and sets appropriate parameters in the login
# page if one is present.
#
# FIXME: Duplicates some of the logic of print_confirm_page but uses slightly
# different template parameters.  This is annoying and should be standardized.
sub get_login_cancel_url {
    my ($lvars, $resp) = @_;
    my $lc = $resp->login_canceled_token;
    my $cancel_url;

    # FIXME: Looks like extra semicolons here too.
    if ($lc) {
        $cancel_url = $resp->return_url . "?WEBAUTHR=$lc;";
        $cancel_url .= ";WEBAUTHS=" . $resp->app_state . ";"
            if $resp->app_state;
    }
    if ($cancel_url) {
        $PAGES{login}->param (login_cancel => 1);
        $PAGES{login}->param (cancel_url => $cancel_url);
    }
    $lvars->{LC} = $cancel_url ? base64_encode ($cancel_url) : '';
    return 0;
}

##############################################################################
# REMOTE_USER support
##############################################################################

# Redirect the user to the REMOTE_USER-enabled login URL.
sub print_remuser_redirect {
    my ($q) = @_;
    my $uri = $WebKDC::Config::REMOTE_USER_REDIRECT;
    unless ($uri) {
        print STDERR "REMOTE_USER_REDIRECT not configured\n" if $LOGGING;
        $PAGES{error}->param (err_webkdc => 1);
        my $errmsg = "unrecoverable error occured. Try again later.";
        $PAGES{error}->param (err_msg => $errmsg);
        print_error_page ($q);
    } else {
        $uri .= "?RT=" . $q->param ('RT') . ";ST=" . $q->param ('ST');
        print STDERR "Redirecting to $uri\n" if $DEBUG;
        print $q->redirect (-uri => $uri);
    }
}

# Generate a proxy token containing the REMOTE_USER identity and pass it into
# the WebKDC along with the other proxy tokens.  Takes the request to the
# WebKDC that we're putting together.  If the REMOTE_USER isn't valid for some
# reason, log an error and don't do anything else.
sub add_remuser_token {
    my ($req) = @_;
    print STDERR "adding a REMOTE_USER token for $ENV{REMOTE_USER}\n"
        if $DEBUG;
    my $keyring = keyring_read_file ($WebKDC::Config::KEYRING_PATH);
    unless ($keyring) {
        warn "weblogin: unable to initialize a keyring from"
            . " $WebKDC::Config::KEYRING_PATH\n";
        return;
    }

    # Make sure that any realm in REMOTE_USER matches the realm specified in
    # our configuration file.  Note that if a realm is specified in the
    # configuration file, it must be present in REMOTE_USER.
    my ($user, $realm) = split ('@', $ENV{REMOTE_USER}, 2);
    if ($WebKDC::Config::REALM) {
        if (!$realm || $realm ne $WebKDC::Config::REALM) {
            warn "weblogin: realm mismatch in REMOTE_USER $ENV{REMOTE_USER}:"
                . ' saw ' . ($realm ? $realm : '""') . " expected "
                . $WebKDC::Config::REALM . "\n";
            return;
        }
    } elsif (@WebKDC::Config::REALMS) {
        my $found = 0;
        $realm ||= '';
        for my $check (@WebKDC::Config::REALMS) {
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
    } elsif ($realm) {
        warn "weblogin: found realm in REMOTE_USER but no realm configured\n";
        return;
    }

    # Create a proxy token.
    my $token = new WebKDC::WebKDCProxyToken;
    $token->creation_time (time);
    $token->expiration_time (time + $WebKDC::Config::REMUSER_EXPIRES);
    $token->proxy_data ($user);
    $token->proxy_subject ('WEBKDC:remuser');
    $token->proxy_type ('remuser');
    $token->subject ($user);

    # Add the token to the WebKDC request.
    my $token_string = base64_encode ($token->to_token ($keyring));
    $req->proxy_cookie ('remuser', $token_string);
}

##############################################################################
# Main routine
##############################################################################

# Pre-compile our templates.  When running under FastCGI, this results in a
# significant speedup, since loading and compiling the templates is a bit
# time-consuming.
%PAGES = map {
    $_ => HTML::Template->new (filename => $PAGES{$_}, cache => 1,
                               path => $WebKDC::Config::TEMPLATE_PATH)
} keys %PAGES;

# The main loop.  If we're not running under FastCGI, CGI::Fast will detect
# that and only run us through the loop once.  Otherwise, we live in this
# processing loop until the FastCGI socket closes.
while (my $q = CGI::Fast->new) {
    my $req = new WebKDC::WebRequest;
    my $resp = new WebKDC::WebResponse;
    my ($status, $exception);

    # If we already have return_url in the query, we're at the confirmation
    # page and the user has changed the REMOTE_USER configuration.  Set or
    # clear the cookie and then redisplay the confirmation page.
    if (defined $q->param ('return_url')) {
        redisplay_confirm_page ($q);
        next;
    }

    # If we got our parameters via REDIRECT_QUERY_STRING, we're an error
    # handler and don't want to redirect later.
    my $is_error = defined $ENV{REDIRECT_QUERY_STRING};

    # If there isn't a request token, display an error message and then skip
    # to the next request.
    unless (defined $q->param ('RT') && defined $q->param ('ST')) {
        $PAGES{error}->param (err_no_request_token => 1);
        print STDERR ("there was no request or service token\n") if $LOGGING;
        print_error_page ($q);
        next;
    }

    # Set up the parameters to the WebKDC request.
    $req->pass ($q->param ('password')) if $q->param ('password');
    $req->user ($q->param ('username'))
        if ($q->param('password') && $q->param('username'));
    $req->service_token (fix_token ($q->param ('ST')));
    $req->request_token (fix_token ($q->param ('RT')));

    # Also pass to the WebKDC any proxy tokens we have from cookies.
    # Enumerate through all cookies that start with webauth_wpt (Webauth Proxy
    # Token) and stuff them into the WebKDC request.
    my %cart = CGI::Cookie->fetch;
    my $wpt_cookie;
    for (keys %cart) {
        if (/^webauth_wpt/) {
            my ($name, $val) = split ('=', $cart{$_});
            $name=~ s/^(webauth_wpt_)//;
            $req->proxy_cookie ($name, $q->cookie ($_));
            print STDERR "found a cookie $name\n" if $DEBUG;
            $wpt_cookie = 1;
        }
    }

    # Pass in the network connection information.  This used to be used for an
    # S/Ident callback and now is no longer used, but maybe someday it will be
    # used for something else.
    $req->local_ip_addr ($ENV{SERVER_ADDR});
    $req->local_ip_port ($ENV{SERVER_PORT});
    $req->remote_ip_addr ($ENV{REMOTE_ADDR});
    $req->remote_ip_port ($ENV{REMOTE_PORT});

    # If WebKDC::Config::HONOR_REMOTE_USER is set to a true value, cobble up a
    # proxy token using the value of REMOTE_USER and add it to the request.
    # This allows the WebKDC to trust Apache authentication mechanisms like
    # SPNEGO or client-side certificates if so configured.  Either way, pass
    # the REMOTE_USER into the WebKDC for logging purposes.
    if ($ENV{REMOTE_USER} && $WebKDC::Config::HONOR_REMOTE_USER) {
        add_remuser_token ($req);
    }
    $req->remote_user ($ENV{REMOTE_USER});

    # Pass the information along to the WebKDC and get the repsonse.
    ($status, $exception) = WebKDC::make_request_token_request ($req, $resp);

    # Parse the result from the WebKDC and get the login cancel information if
    # any.  (The login cancel stuff is oddly placed here, like it was added as
    # an afterthought, and should probably be handled in a cleaner fashion.)
    my %varhash = map { $_ => $q->param ($_) } $q->param;
    get_login_cancel_url (\%varhash, $resp);
    if ($status == WK_SUCCESS && parse_uri (\%varhash, $resp)) {
        $status = WK_ERR_WEBAUTH_SERVER_ERROR;
    }

    # If this page was the result of a form submission (meaning that the user
    # went through the regular login page and, more importantly, has already
    # definitely seen a weblogin page), and the test cookie was not set, make
    # sure we bounce them back to the login page since otherwise WebAuth is
    # going to fail later.
    my $has_cookies = 1;
    if ($q->param ('login')) {
        unless ($q->cookie ($TEST_COOKIE)) {
            $has_cookies = 0;
        }
    }

    # Now, display the appropriate page.  If $status is WK_SUCCESS, we have a
    # successful authentication (by way of proxy token or username/password
    # login).  Otherwise, WK_ERR_USER_AND_PASS_REQUIRED indicates the first
    # visit to the login page, WK_ERR_LOGIN_FAILED indicates the user needs to
    # try logging in again, and WK_ERR_LOGIN_FORCED indicates this site
    # requires username/password even if the user has other auth methods.
    if ($status == WK_SUCCESS && $has_cookies) {
        print_confirm_page ($q, \%varhash, $resp);
        print STDERR ("WebKDC::make_request_token_request sucess\n")
            if $DEBUG;

    # Other authentication methods can be used, REMOTE_USER support is
    # requested by cookie, we're not already at the REMOTE_USER-authenticated
    # URL, and we're not an error handler (meaning that we haven't tried
    # REMOTE_USER and failed).  Redirect to the REMOTE_USER URL.
    } elsif ($status == WK_ERR_USER_AND_PASS_REQUIRED
             && !$ENV{REMOTE_USER}
             && $q->cookie ($REMUSER_COOKIE)
             && !$is_error
             && !$q->param ('login')
             && $WebKDC::Config::REMOTE_USER_REDIRECT) {
        print STDERR ("redirecting to REMOTE_USER page\n") if $DEBUG;
        print_remuser_redirect ($q);

    # The user didn't already ask for REMOTE_USER.  However, we just need
    # authentication (not forced login) and we haven't already tried
    # REMOTE_USER and failed, so give them the login screen with the choice.
    } elsif ($status == WK_ERR_USER_AND_PASS_REQUIRED
             && !$q->cookie ($REMUSER_COOKIE)
             && !$is_error
             && $WebKDC::Config::REMOTE_USER_REDIRECT) {
        $varhash{remuser_url} = $WebKDC::Config::REMOTE_USER_REDIRECT;
        print_login_page ($q, \%varhash, $status, $resp, $req->request_token,
                          $req->service_token);
        print STDERR ("WebKDC::make_request_token_request failed,"
                      . " displaying login page (REMOTE_USER allowed)\n")
            if $DEBUG;

    # We've tried REMOTE_USER and failed, the site has said that the user has
    # to use username/password no matter what, REMOTE_USER redirects are not
    # supported, or the user has already tried username/password.  Display the
    # login screen without the REMOTE_USER choice.
    } elsif ($status == WK_ERR_USER_AND_PASS_REQUIRED
             || $status == WK_ERR_LOGIN_FORCED
             || $status == WK_ERR_LOGIN_FAILED
             || !$has_cookies) {
        if ($WebKDC::Config::REMOTE_USER_REDIRECT) {
            $varhash{remuser_failed} = $is_error;
        }

        # If logins were forced, we want to tell the user.  However, if this
        # is the first site they've authenticated to, we only want to tell the
        # user that if they request REMUSER support.  So, if forced login was
        # set *and* either the user has single sign-on cookies or wants to do
        # REMUSER, set the relevant template variable.
        if ($status == WK_ERR_LOGIN_FORCED
            && ($wpt_cookie || $q->cookie ($REMUSER_COOKIE))) {
            $varhash{forced_login} = 1;
        }

        print_login_page ($q, \%varhash, $status, $resp, $req->request_token,
                          $req->service_token);
        print STDERR ("WebKDC::make_request_token_request failed,"
                      . " displaying login page (REMOTE_USER not allowed)\n")
            if $DEBUG;

    # Something abnormal happened.  Figure out what error message to display
    # and throw up the error page instead.
    } else {
        my $errmsg;

        # Something very nasty.  Just display a "we don't know" error.
        if ($status == WK_ERR_UNRECOVERABLE_ERROR) {
            $errmsg = "unrecoverable error occured. Try again later.";

        # User took too long to login and the original request token is stale.
        } elsif ($status == WK_ERR_REQUEST_TOKEN_STALE) {
            $errmsg = "you took too long to login.";

        # Like WK_ERR_UNRECOVERABLE_ERROR, but indicates the error most likely
        # is due to the webauth server making the request, so stop but display
        # a different error messaage.
        } elsif ($status == WK_ERR_WEBAUTH_SERVER_ERROR) {
            $errmsg = "there is most likely a configuration problem with"
                . " the server that redirected you. Please contact its"
                . " administrator";
        }

        # Display the error page.
        print STDERR "WebKDC::make_request_token_request failed with"
            . " $errmsg: $exception\n" if $LOGGING;
        $PAGES{error}->param (err_webkdc => 1);
        $PAGES{error}->param (err_msg => $errmsg);
        print_error_page ($q);
    }

# Done on each pass through the FastCGI loop.  Clear out template parameters
# for all of the pages for the next run and restart the script if its
# modification time has changed.
} continue {
    for (keys %PAGES) {
        $PAGES{$_}->clear_params;
    }
    exit if -M $ENV{SCRIPT_FILENAME} < 0;
}
