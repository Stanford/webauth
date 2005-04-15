#!/usr/bin/perl -w
our $ID = q($Id$ );
#
# login.fcgi -- Weblogin login page for WebAuth.
#
# Written by Roland Schemers <schemers@stanford.edu>
# Copyright 2002, 2003, 2004 Board of Trustees, Leland Stanford Jr. University
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
use WebAuth3 qw(:base64 :const :krb5 :key);
use WebKDC ();
use WebKDC::Config ();
use WebKDC::WebKDCException;
use URI ();

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
# cookies to set as parameters, and always adds the test cookie.
sub print_headers {
    my ($q, $cookies) = @_;
    my $ca;

    my $secure = (defined ($ENV{HTTPS}) && $ENV{HTTPS} eq 'on') ? 1 : 0;
    if ($cookies) {
        my ($name, $value);
        while (($name, $value) = each %$cookies) {
            my $cookie = $q->cookie(-name => $name, -value => $value,
                                    -secure => $secure);
            push (@$ca, $cookie);
        }
    }
    unless ($q->cookie ($TEST_COOKIE)) {
        my $cookie = $q->cookie (-name => $TEST_COOKIE, -value => 'True',
                                 -path => '/');
        push (@$ca, $cookie);
    }
    if ($ca) {
        print $q->header (-type => 'text/html', -cookie => $ca);
    } else {
        print $q->header (-type => 'text/html');
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

    return 0;
}

# Print the login page.  Takes the query, the variable hash, the WebKDC
# response, the request token, and the service token, and encodes them as
# appropriate in the login page.
sub print_login_page {
    my ($q, $lvars, $resp, $RT, $ST) = @_;
    $PAGES{login}->param ('username' => $lvars->{username});
    $PAGES{login}->param ('RT' => $RT);
    $PAGES{login}->param ('ST' => $ST);
    $PAGES{login}->param ('LC' => $lvars->{LC});
    print_headers ($q, $resp->proxy_cookies);
    print $PAGES{login}->output;
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

# Set various error parameters for the login page, which will be used to
# display the appropriate error message when the login page is displayed.
# Takes the WebKDC status to know whether login failed.  Only do something if
# we got here as the result of a form submission (meaning this wasn't the
# initial view of the login page).
sub set_page_error {
    my ($q, $err) = @_;
    my $page = $PAGES{login};
    if ($q->param ('Submit') && $q->param ('Submit') eq 'Login') {
        $page->param (err_password => 1) unless $q->param ('password');
        $page->param (err_username => 1) unless $q->param ('username');
        $page->param (err_cookies => 1) unless $q->cookie ($TEST_COOKIE);
        $page->param (err_missinginput => 1) if $page->param ('err_username');
        $page->param (err_missinginput => 1) if $page->param ('err_password');
        if ($err == WK_ERR_LOGIN_FAILED) {
            $page->param (login_failed => 1);
        }
    }
    return 0;
}

# Given the query, the local variables, and the WebKDC response, print the
# login page, filling in all of the various bits of data that the page
# template needs.
sub print_confirm_page {
    my ($q, $lvars, $resp) = @_;

    my $pretty_return_url = $lvars->{scheme} . "://" . $lvars->{host};
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

    # Print out the page, including any updated proxy cookies if needed.
    print_headers ($q, $resp->proxy_cookies);
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
        $PAGES{login}->param (wa_cancel_url => 1);
        $PAGES{login}->param (cancel_url => $cancel_url);
    }
    $lvars->{LC} = $cancel_url ? base64_encode ($cancel_url) : '';
    return 0;
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
    my %varhash = map { $_ => $q->param ($_) } $q->param;

    my $req = new WebKDC::WebRequest;
    my $resp = new WebKDC::WebResponse;
    my ($status, $exception);

    # If there isn't a request token, display an error message and then skip
    # to the next request.
    unless (defined $q->param ('RT')) {
        $PAGES{error}->param (err_no_request_token => 1);
        print STDERR ("there was no request token\n") if $LOGGING;
        print_error_page ($q);
        next;
    }

    # Set up the parameters to the WebKDC request.
    $req->pass ($q->param ('password')) if $q->param ('password');
    $req->user ($q->param ('username'))
        if ($q->param('password') && $q->param('username'));
    $req->service_token (fix_token ($q->param ('ST')));
    $req->request_token (fix_token ($q->param ('RT')));

    # Also pass to the WebKDC any proxy tokens we hvae from cookies.
    # Enumerate through all cookies that start with webauth_wpt (Webauth Proxy
    # Token) and stuff them into the WebKDC request.
    my %cart = CGI::Cookie->fetch;
    for (keys %cart) {
        if (/^webauth_wpt/) {
            my ($name, $val) = split ('=', $cart{$_});
            $name=~ s/^(webauth_wpt_)//;
            $req->proxy_cookie ($name, $q->cookie ($_));
            print STDERR "found a cookie $name\n" if $DEBUG;
        }
    }

    # Pass in the network connection information for an S/Ident callback.
    $req->local_ip_addr ($ENV{SERVER_ADDR});
    $req->local_ip_port ($ENV{SERVER_PORT});
    $req->remote_ip_addr ($ENV{REMOTE_ADDR});
    $req->remote_ip_port ($ENV{REMOTE_PORT});

    # Pass the information along to the WebKDC and get the repsonse.
    ($status, $exception) = WebKDC::make_request_token_request ($req, $resp);

    # Parse the result from the WebKDC and get the login cancel information if
    # any.  (The login cancel stuff is oddly placed here, like it was added as
    # an afterthought, and should probably be handled in a cleaner fashion.)
    get_login_cancel_url (\%varhash, $resp);
    if ($status == WK_SUCCESS && parse_uri (\%varhash, $resp)) {
        $status = WK_ERR_WEBAUTH_SERVER_ERROR;
    }

    # If this page was the result of a form submission (meaning that the user
    # went through the regular login page and, more importantly, has already
    # definitely seen a weblogin page), and the test cookie was not set,
    # bounce them back to the login page with an error message.
    my $has_cookies = 1;
    if ($q->param ('Submit') && $q->param ('Submit') eq 'Login') {
        unless ($q->cookie ($TEST_COOKIE)) {
            $has_cookies = 0;
        }
    }

    # Now, display the appropriate page.  If $status is WK_SUCCESS, we have a
    # successful authentication (by way of proxy token, username/password
    # login, or S/Ident).  Otherwise, WK_ERR_USER_AND_PASS_REQUIRED indicates
    # the first visit to the login page without S/Ident, or where S/Ident
    # isn't allowed, and WK_ERR_LOGIN_FAILED indicates the user needs to try
    # logging in again.
    if ($status == WK_SUCCESS && $has_cookies) {
        print_confirm_page ($q, \%varhash, $resp);
        print STDERR ("WebKDC::make_request_token_request sucess\n")
            if $DEBUG;

    # Otherwise, WK_ERR_USER_AND_PASS_REQUIRED indicates the first visit to
    # the login page without S/Ident, or where S/Ident isn't allowed, and
    # WK_ERR_LOGIN_FAILED indicates the user needs to try logging in again.
    } elsif ($status == WK_ERR_USER_AND_PASS_REQUIRED
             || $status == WK_ERR_LOGIN_FAILED
             || !$has_cookies) {
        set_page_error ($q, $status);
        print_login_page ($q, \%varhash, $resp, $req->request_token,
                          $req->service_token);
        print STDERR ("WebKDC::make_request_token_request failed,"
                      . " displaying login page\n") if $DEBUG;

    # Finally, some sort of error could have occurred.  Figure out what error
    # and display an appropriate error page.
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

        print STDERR "WebKDC::make_request_token_request failed with"
            . " $errmsg: $exception\n";
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
