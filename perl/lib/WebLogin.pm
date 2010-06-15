# WebLogin interactions with the browser for WebAuth
#
# Written by Roland Schemers <schemers@stanford.edu>
# Extensive updates by Russ Allbery <rra@stanford.edu>
# Copyright 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
#     Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package WebLogin;

require 5.006;

use strict;
use warnings;

use CGI ();
use CGI::Cookie ();
use CGI::Fast ();
use HTML::Template ();
use WebAuth qw(:base64 :const :krb5 :key);
use WebKDC ();
use WebKDC::Config ();
use WebKDC::WebKDCException;
use URI ();
use URI::QueryParam ();

# These are required only if we are going to check for expiring passwords.
if ($WebKDC::Config::EXPIRING_PW_SERVER) {
    require Date::Parse;
    require Time::Duration;
    require Net::Remctl;
}

# Set to true in order to enable debugging output.  This will be very chatty
# in the logs and may log security-sensitive tokens and other information.
our $DEBUG = 0;

# Set to true to log interesting error messages to stderr.
our $LOGGING = 1;

# The name of the cookie we set to ensure that the browser can handle cookies.
our $TEST_COOKIE = "WebloginTestCookie";

# The name of the cookie holding REMOTE_USER configuration information.
our $REMUSER_COOKIE = 'weblogin_remuser';

# The lifetime of the REMOTE_USER configuration cookie.
our $REMUSER_LIFETIME = '+365d';

# The lifetime of the kadmin/changepw token.
our $CHANGEPW_EXPIRES = 5 * 60;

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

##############################################################################
# Output
##############################################################################

# Print the headers for a page.  Takes the user's query and any additional
# cookies to set as parameters, and always adds the test cookie.  Skip any
# remuser proxy tokens, since those are internal and we want to reauthenticate
# the user every time.  Takes an optional redirection URL and an optional
# parameter saying that this is a post redirect.
sub print_headers {
    my ($self, $cookies, $redir_url, $post) = @_;
    my $q = $self->{query};
    my $ca;

    # REMUSER_COOKIE is handled as a special case, since it stores user
    # preferences and should be retained rather than being only a session
    # cookie.
    my $secure = (defined ($ENV{HTTPS}) && $ENV{HTTPS} eq 'on') ? 1 : 0;
    my $saw_remuser;
    if ($cookies) {
        my ($name, $value);
        while (($name, $value) = each %$cookies) {
            next if $name eq 'webauth_wpt_remuser';
            my $cookie;
            if ($name eq $self->{remuser_cookie}) {
                $cookie = $q->cookie(-name    => $name,
                                     -value   => $value,
                                     -secure  => $secure,
                                     -expires => $self->{remuser_lifetime});
                $saw_remuser = 1;
            } else {
                $cookie = $q->cookie(-name   => $name,
                                     -value  => $value,
                                     -secure => $secure);
            }
            push (@$ca, $cookie);
        }
    }

    # If we're not setting the REMUSER_COOKIE cookie explicitly and it was
    # set in the query, set it in our page.  This refreshes the expiration
    # time of the cookie so that, provided the user visits WebLogin at least
    # once a year, the cookie will never expire.
    if (!$saw_remuser && $q->cookie ($self->{remuser_cookie})) {
        my $cookie = $q->cookie (-name    => $self->{remuser_cookie},
                                 -value   => 1,
                                 -secure  => $secure,
                                 -expires => $self->{remuser_lifetime});
        push (@$ca, $cookie);
    }

    # Set the test cookie unless it's already set.
    unless ($q->cookie ($self->{test_cookie})) {
        my $cookie = $q->cookie (-name  => $self->{test_cookie},
                                 -value => 'True',
                                 -path  => '/',
                                 -secure => $secure);
        push (@$ca, $cookie);
    }

    # Now, print out the page header with the appropriate cookies.
    my @params;
    if ($redir_url) {
        push (@params, -location => $redir_url,
              -status => $post ? '303 See Also' : '302 Moved');
    }
    push (@params, -cookie => $ca) if $ca;
    print $q->header (-type => 'text/html', -Pragma => 'no-cache',
                      -Cache_Control => 'no-cache, no-store', @params);
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

# Parse the return URL of our request, filling out the provided lvars struct
# with the details.  Make sure that the scheme exists and is a valid WebAuth
# scheme.  Return 0 if everything is okay, 1 if the scheme is invalid.
sub parse_uri {
    my ($self) = @_;
    my $resp = $self->{response};
    my $uri = URI->new ($resp->return_url);

    $self->{lvars}->{return_url} = $uri->canonical;
    my $scheme = $uri->scheme;
    unless (defined ($scheme) && $scheme =~ /^https?$/) {
        $self->{pages}->{error}->param (err_webkdc => 1);
        return 1;
    }
    $self->{lvars}->{scheme} = $scheme;
    $self->{lvars}->{host}   = $uri->host;
    $self->{lvars}->{path}   = $uri->path;
    $self->{lvars}->{port}   = $uri->port if ($uri->port != 80
                                              && $uri->port != 443);
    $self->{lvars}->{pretty} = $self->pretty_return_uri ($uri);

    return 0;
}

# Print the login page.  Takes the query, the variable hash, the error code if
# any, the WebKDC response, the request token, and the service token, and
# encodes them as appropriate in the login page.
sub print_login_page {
    my ($self, $err, $RT, $ST) = @_;
    my $q = $self->{query};
    my $resp = $self->{response};
    my $page = $self->{pages}->{login};

    $page->param (script_name => $self->{script_name});
    $page->param (username => $self->{lvars}->{username});
    $page->param (RT => $RT);
    $page->param (ST => $ST);
    $page->param (LC => $self->{lvars}->{LC});
    if ($self->{lvars}->{remuser_url}) {
        $page->param (show_remuser => 1);
        $page->param (remuser_url => $self->{lvars}->{remuser_url});
    }
    if ($self->{lvars}->{remuser_failed}) {
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
        $page->param (err_missinginput => 1) if $page->param ('err_username');
        $page->param (err_missinginput => 1) if $page->param ('err_password');
        if ($err == WK_ERR_LOGIN_FAILED) {
            $page->param (err_loginfailed => 1);
        }
        if ($err == WK_ERR_USER_REJECTED) {
            $page->param (err_rejected => 1);
        }

        # Set a generic error indicator if any of the specific ones were set
        # to allow easier structuring of the login page template.
        $page->param (error => 1) if $page->param ('err_missinginput');
        $page->param (error => 1) if $page->param ('err_loginfailed');
        $page->param (error => 1) if $page->param ('err_rejected');
    } elsif ($self->{lvars}->{forced_login}) {
        $page->param (err_forced => 1);
        $page->param (error => 1);
    }
    $self->print_headers ($resp->proxy_cookies);
    print $page->output;
}

# Print an error page, making sure that error pages are never cached.
sub print_error_page {
    my ($self) = @_;
    my $q = $self->{query};
    print $q->header (-expires => 'now');
    print $self->{pages}->{error}->output;
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
    return $rights;
}

# Given the query, the local variables, and the WebKDC response, print the
# login page, filling in all of the various bits of data that the page
# template needs.
sub print_confirm_page {
    my ($self) = @_;
    my $q = $self->{query};
    my $resp = $self->{response};
    my $page = $self->{pages}->{confirm};

    my $pretty_return_url = $self->{lvars}->{pretty};
    my $return_url = $resp->return_url;
    my $lc = $resp->login_canceled_token;
    my $token_type = $resp->response_token_type;

    # FIXME: This looks like it generates extra, unnecessary semicolons, but
    # should be checked against the parser in the WebAuth module.
    $return_url .= "?WEBAUTHR=" . $resp->response_token . ";";
    $return_url .= ";WEBAUTHS=" . $resp->app_state . ";" if $resp->app_state;

    # Find out if the user is within the window to have a password expiration
    # warning.  Skip if using remote_user or the user already has a
    # single-sign-on cookie.
    my $expire_warning = 0;
    if (!$q->cookie ($self->{remuser_cookie}) && !$self->{wpt_cookie}
        && $WebKDC::Config::EXPIRING_PW_URL) {

        my $expiring = $self->time_to_pwexpire;
        if (defined $expiring
            && (($expiring - time) < $WebKDC::Config::EXPIRING_PW_WARNING)) {

            $expire_warning = 1;
            my $expire_date = localtime ($expiring);
            my $countdown = Time::Duration::duration ($expiring - time);
            $page->param (warn_expire => 1);
            $page->param (expire_date => $expire_date);
            $page->param (expire_time_left => $countdown);
            $page->param (pwchange_url
                          => $WebKDC::Config::EXPIRING_PW_URL);

            # Create and set the kadmin/changepw token.
            $self->add_changepw_token;
            $page->param (CPT => $self->{CPT});
        }
    }

    # If configured to permit bypassing the confirmation page, the WAS
    # requested an id token (not a proxy token, which may indicate ticket
    # delegation), and the page was not the target of a POST, return a
    # redirect to the final page instead of displaying a confirmation page.
    # If the page was the target of the post, we'll return a 303 redirect
    # later on but present the regular confirmation page as the body in case
    # the browser doesn't support it.  We also skip the bypass if the user
    # has an upcoming password expiration warning.
    my $bypass = $WebKDC::Config::BYPASS_CONFIRM;
    $bypass = 0 if $expire_warning;
    if ($bypass and $bypass eq 'id') {
        $bypass = ($token_type eq 'id') ? 1 : 0;
    }
    if ($token_type eq 'id') {
        if ($bypass and not $self->{lvars}->{force_confirm}) {
            $self->print_headers ($resp->proxy_cookies, $return_url);
            return;
        }
    }

    # Find our page and set general template parameters.  token_rights was
    # added in WebAuth 3.6.1.  Adjust for older templates.
    $page->param (return_url => $return_url);
    $page->param (username => $resp->subject);
    $page->param (pretty_return_url => $pretty_return_url);
    if ($token_type eq 'proxy' and $page->query (name => 'token_rights')) {
        $page->param (token_rights => $self->token_rights);
    }

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
    if ($WebKDC::Config::REMUSER_REDIRECT) {
        if ($ENV{REMOTE_USER} || $q->cookie ($self->{remuser_cookie})) {
            $page->param (show_remuser => 1);
            if ($q->cookie ($self->{remuser_cookie})) {
                $page->param (remuser => 1);
            }

            $page->param (script_name => $self->{script_name});
        }
    }

    # Print out the page, including any updated proxy cookies if needed.  If
    # we're suppressing the confirm page and the browser used HTTP/1.1, use
    # the HTTP 303 redirect code as well.
    if ($bypass && $ENV{SERVER_PROTOCOL} eq 'HTTP/1.1') {
        $self->print_headers ($resp->proxy_cookies, $return_url, 1);
    } else {
        $self->print_headers ($resp->proxy_cookies);
    }
    print $page->output;
}

# Given the query, redisplay the confirmation page after a change in the
# REMOTE_USER cookie.  Also set the new REMOTE_USER cookie.
#
# FIXME: We lose the token rights.  Maybe we should preserve the identity of
# the WAS in a hidden variable?
sub redisplay_confirm_page {
    my ($self) = @_;
    my $q = $self->{query};

    my $return_url = $q->param ('return_url');
    my $username = $q->param ('username');
    my $cancel_url = $q->param ('cancel_url');

    my $uri = URI->new ($return_url);
    unless ($username && $uri && $uri->scheme && $uri->host) {
        $self->{pages}->{error}->param (err_confirm => 1);
        print STDERR "missing data when reconstructing confirm page\n"
            if $self->{logging};
        $self->print_error_page;
        return;
    }
    my $pretty_return_url = $self->pretty_return_uri ($uri);

    # Find our page and set general template parameters.
    my $page = $self->{pages}->{confirm};
    $page->param (return_url => $return_url);
    $page->param (username => $username);
    $page->param (pretty_return_url => $pretty_return_url);
    $page->param (script_name => $self->{script_name});
    $page->param (show_remuser => 1);
    my $remuser = $q->param ('remuser') eq 'on' ? 'checked' : '';
    $page->param (remuser => $remuser);

    # If there is a login cancel option, handle creating the link for it.
    if (defined $cancel_url) {
        $page->param (login_cancel => 1);
        $page->param (cancel_url => $cancel_url);
    }

    # Print out the page, including the new REMOTE_USER cookie.
    $self->print_headers ({ $self->{remuser_cookie} => ($remuser ? 1 : 0) });
    print $page->output;
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
        $self->{pages}->{login}->param (login_cancel => 1);
        $self->{pages}->{login}->param (cancel_url => $cancel_url);
    }
    $self->{lvars}->{LC} = $cancel_url ? base64_encode ($cancel_url) : '';
    return 0;
}

# Print the password change page.
sub print_pwchange_page {
    my ($self, $RT, $ST) = @_;
    my $q = $self->{query};
    my $page = $self->{pages}->{pwchange};

    # Get and pass along various field values that remain across attempts.
    my $username = $q->param ('username');
    $page->param (username => $username);
    $page->param (CPT => $self->{CPT});
    $page->param (RT => $RT);
    $page->param (ST => $ST);
    $page->param (script_name => $self->{script_name});
    $page->param (expired => 1) if $q->param ('expired') == 1;

    # We don't need the user information if they have already acquired a
    # kadmin/changepw token.
    if ($self->{CPT}) {
        $page->param (skip_username => 1);
        $page->param (skip_password => 1);
    }

    # Print out the page.
    $self->print_headers;
    print $page->output;
}

# Print confirmation page after successful password change.  This is only
# hit when not having been sent here with an expired password.
sub print_pwchange_confirm_page {
    my ($self) = @_;
    my $q = $self->{query};
    my $page = $self->{pages}->{pwchange};

    $page->param (success => 1);
    $self->print_headers;
    print $page->output;
}

##############################################################################
# REMOTE_USER support
##############################################################################

# Redirect the user to the REMOTE_USER-enabled login URL.
sub print_remuser_redirect {
    my ($self) = @_;
    my $q = $self->{query};
    my $uri = $WebKDC::Config::REMUSER_REDIRECT;

    unless ($uri) {
        print STDERR "REMUSER_REDIRECT not configured\n"
            if $self->{logging};
        $self->{pages}->{error}->param (err_webkdc => 1);
        my $errmsg = "unrecoverable error occured. Try again later.";
        $self->{pages}->{error}->param (err_msg => $errmsg);
        $self->print_error_page;
    } else {
        $uri .= "?RT=" . $self->fix_token ($q->param ('RT')) .
                ";ST=" . $self->fix_token ($q->param ('ST'));
        print STDERR "redirecting to $uri\n" if $self->{debug};
        print $q->redirect (-uri => $uri);
    }
}

# Generate a proxy token using forwarded credentials and pass it into the
# WebKDC with the other proxy tokens.
sub add_proxy_token {
    my ($self) = @_;

    print STDERR "adding a proxy token for $ENV{REMOTE_USER}\n"
        if $self->{debug};
    my ($kreq, $data);
    my $principal = $WebKDC::Config::WEBKDC_PRINCIPAL;
    eval {
        my $context = krb5_new;
        krb5_init_via_cache ($context);
        my ($tgt, $expires) = krb5_export_tgt ($context);
        ($kreq, $data) = krb5_mk_req ($context, $principal, $tgt);
        $kreq = base64_encode ($kreq);
        $data = base64_encode ($data);
    };
    if ($@) {
        print STDERR "failed to create proxy token request for"
            . " $ENV{REMOTE_USER}: $@\n" if $self->{logging};
        return;
    }
    my ($status, $error, $token, $subject)
        = WebKDC::make_proxy_token_request ($kreq, $data);
    if ($status != WK_SUCCESS) {
        print STDERR "failed to obtain proxy token for $ENV{REMOTE_USER}:"
            . " $error\n" if $self->{logging};
        return;
    }
    print STDERR "adding krb5 proxy token for $subject\n" if $self->{debug};
    $self->{request}->proxy_cookie ('krb5', $token);
}

# Generate a proxy token containing the REMOTE_USER identity and pass it into
# the WebKDC along with the other proxy tokens.  Takes the request to the
# WebKDC that we're putting together.  If the REMOTE_USER isn't valid for some
# reason, log an error and don't do anything else.
sub add_remuser_token {
    my ($self) = @_;

    print STDERR "adding a REMOTE_USER token for $ENV{REMOTE_USER}\n"
        if $self->{debug};
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
    if (@WebKDC::Config::REMUSER_REALMS) {
        my $found = 0;
        $realm ||= '';
        for my $check (@WebKDC::Config::REMUSER_REALMS) {
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
    $self->{request}->proxy_cookie ('remuser', $token_string);
}

##############################################################################
# Password change functions
##############################################################################

# Create a kadmin/changepw token using the username and password.
sub add_changepw_token {
    my ($self) = @_;
    my $q = $self->{query};
    my $username = $q->param ('username');
    my $password = $q->param ('password');

    # Don't bother if the token already is created.
    return if $self->{CPT};

    print STDERR "adding a kadmin/changepw cred token for $username\n"
        if $self->{debug};

    # Create a ticket for kadmin/changepw with the user name and password.
    my ($ticket, $expires);
    eval {
        my $context = krb5_new;
        krb5_init_via_password ($context, $username, $password,
                                'kadmin/changepw', '', '');
        ($ticket, $expires) = krb5_export_ticket ($context,
                                                  'kadmin/changepw');
    };
    if ($@) {
        print STDERR "failed to create kadmin/changepw credential for"
            . " $username: $@\n" if $self->{logging};
        return;
    }

    # Token expires the sooner of when the ticket expires or our time limit.
    my $expires_limit = time + $CHANGEPW_EXPIRES;
    $expires = $expires_limit if $expires_limit < $expires;

    # Create the token to contain the credential.
    my $token = new WebKDC::CredToken;
    $token->creation_time (time);
    $token->expiration_time ($expires);
    $token->cred_type ('krb5');
    $token->cred_data ($ticket);
    $token->subject ($username);

    # Add the token to the web page.
    my $keyring = keyring_read_file ($WebKDC::Config::KEYRING_PATH);
    unless ($keyring) {
        warn "weblogin: unable to initialize a keyring from"
            . " $WebKDC::Config::KEYRING_PATH\n";
        return;
    }
    $self->{CPT} = base64_encode ($token->to_token ($keyring));
}

# Attempt to change the user password using the changepw token.
sub change_user_password {
    my ($self) = @_;
    my $q = $self->{query};
    my ($status, $error);

    my $username = $q->param ('username');
    my $password = $q->param ('new_passwd1');
    my $cpt = $self->{CPT};

    print STDERR "changing password for $username\n" if $self->{debug};

    my $keyring = keyring_read_file ($WebKDC::Config::KEYRING_PATH);
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
    if (!$cpt && $password) {
        $self->add_changepw_token;
        $cpt = $self->{CPT};
    }
    my $token;
    eval {
        $token = new WebKDC::CredToken (base64_decode ($cpt), $keyring, 0);
    };
    if ($@) {
        $self->{CPT} = '';
        my $msg = "timeout for $username: please re-enter your current "
            ."password";
        my $e = $@;
        if (ref $e and $e->isa('WebKDC::WebKDCException')) {
            print STDERR $e->message(), "\n" if $self->{logging};
            return ($e->status(), $msg);
        } elsif ($e) {
            return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $msg);
        }

    } elsif ($token->subject ne $username) {
        my $e = "failed to change password for $username: invalid username";
        print STDERR $e, "\n" if $self->{logging};
        return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $e);
    } elsif ($token->cred_type ne 'krb5') {
        my $e = "failed to change password for $username: "
            . "invalid credential type";
        print STDERR $e, "\n" if $self->{logging};
        return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $e);
    } elsif ($token->expiration_time < time) {
        my $e = "failed to change password for $username: "
            . "credential token expired";
        print STDERR $e, "\n" if $self->{logging};
        return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $e);
    }

    # Change the password and return any error status plus exception object.
    eval {
        my $context = krb5_new;
        krb5_init_via_cred ($context, $token->cred_data);
        krb5_change_password ($context, $password);
    };
    my $e = $@;
    if (ref $e and $e->isa('WebKDC::WebKDCException')) {
        return ($e->status(), $e->message());
    } elsif ($e) {
        return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $e);
    } else {
        return (WebKDC::WK_SUCCESS, undef);
    }
}

# Given the password expiration time for a user, parse it and compare to
# our current time.  Returns the seconds remaining until the password
# expires, or undef if there is no expiration.
sub time_to_pwexpire {
    my ($self) = @_;
    my $q = $self->{query};

    # Return if we've not set an expired password command.
    return undef unless $WebKDC::Config::EXPIRING_PW_SERVER;

    # FIXME: The kadmin remctl interface isn't going to swallow
    # fully-qualified principal names.  This means that this won't work in
    # a multi-realm situation, currently.  If/when that changes, we should
    # add the default realm to the principal if none is currently there.

    # Get the current password expire time from the server.  Save the current
    # tgt, use the one for password expiration, then restore the old.
    my $username = $q->param ('username');
    my $normaltgt = $ENV{KRB5CCNAME};
    $ENV{KRB5CCNAME} = $WebKDC::Config::EXPIRING_PW_TGT;
    my $result = Net::Remctl::remctl ($WebKDC::Config::EXPIRING_PW_SERVER,
                                      0, '', 'kadmin', 'check_expire',
                                      $username, 'pwexpire');
    $ENV{KRB5CCNAME} = $normaltgt;
    return undef if $result->error;

    my $expiration = $result->stdout;
    chomp $expiration;

    # Empty string should mean there is no password expiration date.  An
    # expiration time that doesn't match the format we expect has us put a
    # warning into the log but not stop page processing.
    return undef unless $expiration;
    if ($expiration !~ /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z$/) {
        print STDERR "invalid password expire time for $username: "
            ."$expiration\n" if $self->{logging};
        return undef;
    }

    return Date::Parse::str2time ($expiration);
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
sub test_cookies {
    my ($self) = @_;

    return 1 if $self->{query}->cookie ($self->{test_cookie});
    if (defined $self->{query}->param ('test_cookie')) {
        print STDERR "no cookie, even after redirection\n"
            if $self->{logging};

        # err_cookies_disabled was added as a form parameter with WebAuth
        # 3.5.5.  Try to adjust for old templates.
        if ($self->{pages}->{error}->query (name => "err_cookies_disabled")) {
            $self->{pages}->{error}->param (err_cookies_disabled => 1);
        } else {
            print STDERR "warning: err_cookies_disabled not recognized"
                . " by WebLogin error template\n" if $self->{logging};
            $self->{pages}->{error}->param (err_webkdc => 1);
            my $message = 'You must enable cookies in your web browser.';
            $self->{pages}->{error}->param (err_msg => $message);
        }
        $self->print_error_page;
        return 0;
    } elsif ($self->{query}->request_method ne 'POST') {
        $self->{query}->delete ('username', 'password', 'submit');
        $self->{query}->param (test_cookie => 1);
        my $redir_url = $self->{query}->url (-query => 1);
        print STDERR "no cookie set, redirecting to $redir_url\n"
            if $self->{debug};
        $self->print_headers ('', $redir_url);
        return 0;
    }

    return 1;
}

# If the user sent a password, force POST as a method.  Otherwise, if we
# continue, the password may show up in referrer strings sent by the
# browser to the remote site.
#
# err_bad_method was added as a form parameter with WebAuth 3.6.2.  Try to
# adjust for old templates.
sub test_password_no_post {
    my ($self) = @_;
    my $q = $self->{query};

    return 1 unless $q->param ('password') && $q->request_method ne 'POST';

    if ($self->{pages}->{error}->query (name => 'err_bad_method')) {
        $self->{pages}->{error}->param (err_bad_method => 1);
    } else {
        print STDERR "warning: err_bad_method not recognized by WebLogin"
            . " error template\n" if $self->{logging};
        $self->{pages}->{error}->param (err_webkdc => 1);
        my $message = 'You must use the POST method to log in.';
        $self->{pages}->{error}->param (err_msg => $message);
    }
    $self->print_error_page;
    return 0;
}

# Check to see if we have a defined request token.  If not, display the
# error page and tell the caller to skip to the next request.
sub test_request_token {
    my ($self) = @_;
    my $q = $self->{query};

    return 1 if defined $q->param ('RT') && defined $q->param ('ST');

    $self->{pages}->{error}->param (err_no_request_token => 1);
    print STDERR "no request or service token\n" if $self->{logging};
    $self->print_error_page;
    return 0;
}

# Test for requirements of a password request:
#   Username (Unless already authed)
#   Current password (Unless already authed)
#   Two prompts for new password (must match)
#
# Check to see if all required fields for a password change form have been
# filled out correctly.  If so, return 1.  If not, print the password
# change page again, with the errors, and return 0.
sub test_pwchange_fields {
    my ($self) = @_;
    my $q = $self->{query};
    my $req = $self->{request};
    my $error;

    # Even if it's a hidden field and not given to user, this should exist.
    if (!$q->param ('username')) {
        $self->{pages}->{pwchange}->param (err_username => 1);
        $error = 1;
    }

    # For password, we do not require it if we already have a kadmin/changepw
    # token.
    if (!$q->param ('password') && !$self->{CPT}) {
        $self->{pages}->{pwchange}->param (err_password => 1);
        $error = 1;

    # Check both for empty new password, and for it to not match itself.
    } elsif (!$q->param ('new_passwd1') || !$q->param ('new_passwd2')) {
        $self->{pages}->{pwchange}->param (err_newpassword => 1);
        $error = 1;
    } elsif ($q->param ('new_passwd1') ne $q->param ('new_passwd2')) {
        $self->{pages}->{pwchange}->param (err_newpassword_match => 1);
        $error = 1;
    }

    return 1 unless $error;

    # Mark us as having had an error and print the page again.
    $self->{pages}->{pwchange}->param (error => 1);
    $self->print_pwchange_page ($req->request_token, $req->service_token);
    return 0;
}

##############################################################################
# Primary page handler
##############################################################################

# Set up all parameters to the WebKDC request, including tokens, username
# and password, proxy tokens, logging information, and REMOTE_USER
# information.  Takes a hash of cookies.
sub setup_kdc_request {
    my ($self, %cart) = @_;
    my ($status);
    my $q = $self->{query};

    # Set up the parameters to the WebKDC request.
    $self->{request}->service_token ($self->fix_token ($q->param ('ST')));
    $self->{request}->request_token ($self->fix_token ($q->param ('RT')));
    $self->{request}->pass ($q->param ('password')) if $q->param ('password');
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
        $self->{request}->user ($username);
    }

    # Also pass to the WebKDC any proxy tokens we have from cookies.
    # Enumerate all cookies that start with webauth_wpt (WebAuth Proxy Token)
    # and stuff them into the WebKDC request.
    my $wpt_cookie;
    for (keys %cart) {
        if (/^webauth_wpt/) {
            my ($name, $val) = split ('=', $cart{$_});
            $name=~ s/^(webauth_wpt_)//;
            $self->{request}->proxy_cookie ($name, $q->cookie ($_));
            print STDERR "found a cookie $name\n" if $self->{debug};
            $wpt_cookie = 1;
        }
    }
    $self->{wpt_cookie} = $wpt_cookie;

    # Pass in the network connection information.  This is only used for
    # additional logging in the WebKDC.
    $self->{request}->local_ip_addr ($ENV{SERVER_ADDR});
    $self->{request}->local_ip_port ($ENV{SERVER_PORT});
    $self->{request}->remote_ip_addr ($ENV{REMOTE_ADDR});
    $self->{request}->remote_ip_port ($ENV{REMOTE_PORT});

    # If WebKDC::Config::REMUSER_ENABLED is set to a true value, see if we
    # have a ticket cache.  If so, obtain a proxy token in advance.
    # Otherwise, cobble up a proxy token using the value of REMOTE_USER and
    # add it to the request.  This allows the WebKDC to trust Apache
    # authentication mechanisms like SPNEGO or client-side certificates if so
    # configured.  Either way, pass the REMOTE_USER into the WebKDC for
    # logging purposes.
    if ($ENV{REMOTE_USER} && $WebKDC::Config::REMUSER_ENABLED) {
        if ($ENV{KRB5CCNAME} && $WebKDC::Config::WEBKDC_PRINCIPAL) {
            $self->add_proxy_token;
        } else {
            $self->add_remuser_token;
        }
    }
    $self->{request}->remote_user ($ENV{REMOTE_USER});
    return $status;
}

# Decide which page we print out based on the response from the KDC, then
# display that page.
sub process_response {
    my ($self, $status, $error) = @_;
    my $q = $self->{query};
    my $req = $self->{request};
    my $resp = $self->{response};

    # Parse the result from the WebKDC and get the login cancel information if
    # any.  (The login cancel stuff is oddly placed here, like it was added as
    # an afterthought, and should probably be handled in a cleaner fashion.)
    $self->get_login_cancel_url;
    if ($status == WK_SUCCESS && $self->parse_uri) {
        $status = WK_ERR_WEBAUTH_SERVER_ERROR;
    }

    # Now, display the appropriate page.  If $status is WK_SUCCESS, we have a
    # successful authentication (by way of proxy token or username/password
    # login).  Otherwise, WK_ERR_USER_AND_PASS_REQUIRED indicates the first
    # visit to the login page, WK_ERR_LOGIN_FAILED indicates the user needs to
    # try logging in again, and WK_ERR_LOGIN_FORCED indicates this site
    # requires username/password even if the user has other auth methods.
    #
    # If username was set, we were the target of a form submission and
    # therefore by protocol must display a real page.  Otherwise, we can
    # return a redirect if BYPASS_CONFIRM is set.
    if ($status == WK_SUCCESS) {
        if (defined (&WebKDC::Config::record_login)) {
            WebKDC::Config::record_login ($resp->subject);
        }
        $self->{lvars}->{force_confirm} = 1 if $q->param ('username');
        $self->print_confirm_page;
        print STDERR "WebKDC::make_request_token_request sucess\n"
            if $self->{debug};

    # User's password has expired.  Get the CPT and update the script name.
    } elsif ($status == WK_ERR_CREDS_EXPIRED) {
        $self->add_changepw_token;
        $self->{script_name} = $WebKDC::Config::EXPIRING_PW_URL;
        $self->{query}->param ('expired', 1);
        $self->print_pwchange_page ($req->request_token, $req->service_token);

    # Other authentication methods can be used, REMOTE_USER support is
    # requested by cookie, we're not already at the REMOTE_USER-authenticated
    # URL, and we're not an error handler (meaning that we haven't tried
    # REMOTE_USER and failed).  Redirect to the REMOTE_USER URL.
    } elsif ($status == WK_ERR_USER_AND_PASS_REQUIRED
             && !$ENV{REMOTE_USER}
             && $q->cookie ($self->{remuser_cookie})
             && !$self->{is_error}
             && !$q->param ('login')
             && $WebKDC::Config::REMUSER_REDIRECT) {
        print STDERR "redirecting to REMOTE_USER page\n" if $self->{debug};
        $self->print_remuser_redirect;

    # The user didn't already ask for REMOTE_USER.  However, we just need
    # authentication (not forced login) and we haven't already tried
    # REMOTE_USER and failed, so give them the login screen with the choice.
    } elsif ($status == WK_ERR_USER_AND_PASS_REQUIRED
             && !$q->cookie ($self->{remuser_cookie})
             && !$self->{is_error}
             && $WebKDC::Config::REMUSER_REDIRECT) {
        $self->{lvars}->{remuser_url} = $WebKDC::Config::REMUSER_REDIRECT;
        $self->print_login_page ($status, $req->request_token,
                                 $req->service_token);
        print STDERR "WebKDC::make_request_token_request failed,"
            . " displaying login page (REMOTE_USER allowed)\n"
            if $self->{debug};

    # We've tried REMOTE_USER and failed, the site has said that the user has
    # to use username/password no matter what, REMOTE_USER redirects are not
    # supported, or the user has already tried username/password.  Display the
    # login screen without the REMOTE_USER choice.
    } elsif ($status == WK_ERR_USER_AND_PASS_REQUIRED
             || $status == WK_ERR_LOGIN_FORCED
             || $status == WK_ERR_LOGIN_FAILED
             || $status == WK_ERR_USER_REJECTED) {
        if ($WebKDC::Config::REMUSER_REDIRECT) {
            $self->{lvars}->{remuser_failed} = $self->{is_error};
        }

        # If logins were forced, we want to tell the user.  However, if this
        # is the first site they've authenticated to, we only want to tell the
        # user that if they request REMUSER support.  So, if forced login was
        # set *and* either the user has single sign-on cookies or wants to do
        # REMUSER, set the relevant template variable.
        if ($status == WK_ERR_LOGIN_FORCED
            && ($self->{wpt_cookie}
                     || $q->cookie ($self->{remuser_cookie}))) {
            $self->{lvars}->{forced_login} = 1;
        }

        $self->print_login_page ($status, $req->request_token,
                                 $req->service_token);
        print STDERR "WebKDC::make_request_token_request failed,"
            . " displaying login page (REMOTE_USER not allowed)\n"
            if $self->{debug};

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
            . " $errmsg: $error\n" if $self->{logging};
        $self->{pages}->{error}->param (err_webkdc => 1);
        $self->{pages}->{error}->param (err_msg => $errmsg);
        $self->print_error_page;
    }
}

##############################################################################
# Constructing the object
##############################################################################

# Create and returns a WebLogin object to handle page processing for a
# request.
sub new {
    my ($class, $query, $pages, %settings)= @_;

    my $self = {};
    bless $self, $class;

    # CGI object for the query objects for the request and response to the
    # webkdc.
    $self->{query} = $query;
    $self->{request} = new WebKDC::WebRequest;
    $self->{response} = new WebKDC::WebResponse;

    # If we got our parameters via REDIRECT_QUERY_STRING, we're an error
    # handler and don't want to redirect later.
    $self->{is_error} = defined $ENV{REDIRECT_QUERY_STRING};

    # A number of HTML::Template objects for each possible webpage.
    $self->{pages} = $pages;

    # Testing and logging - optional.
    $self->{logging} = (exists $settings{logging})
        ? $settings{logging} : $LOGGING;
    $self->{debug} = (exists $settings{debug})
        ? $settings{debug} : $DEBUG;

    # Cookie values - optional.
    $self->{remuser_cookie} = (exists $settings{remuser_cookie})
        ? $settings{remuser_cookie} : $REMUSER_COOKIE;
    $self->{remuser_lifetime} = (exists $settings{remuser_lifetime})
        ? $settings{remuser_lifetime} : $REMUSER_LIFETIME;
    $self->{test_cookie} = (exists $settings{test_cookie})
        ? $settings{test_cookie} : $TEST_COOKIE;

    # Reload CPT from the query each time so that we can properly empty it
    # if it has expired.
    $self->{CPT} = $query->param ('CPT');

    # Track parameters from the pervious request.
    # FIXME: We currently load this, but then also use $query->param in many
    #        places as well.  Standardize on using this, and rename to
    #        something more descriptive.
    my %params = map { $_ => $query->param ($_) } $query->param;
    $self->{lvars} = \%params;

    # Setting up for later.
    $self->{wpt_cookie} = '';

    # Work around a bug in CGI.  Then copy the script name so that it can
    # be easily updated when we switch between password and login scripts.
    $self->{query}->{'.script_name'} = $ENV{SCRIPT_NAME};
    $self->{script_name} = $self->{query}->script_name;
    print STDERR "Script name is ", $self->{query}->script_name, "\n"
        if $self->{debug};

    return $self;
}

##############################################################################
# Documentation
##############################################################################

1;

__END__

=head1 NAME

WebLogin - functions to support the weblogin process

=head1 SYNOPSIS

  use WebLogin;

=head1 DESCRIPTION

WebLogin is a set of functions required by the WebAuth login process itself,
in order to generalize login tasks between scripts.

=head1 EXPORT

None

=head1 FUNCTIONS

=over 4

=back

=head1 AUTHOR

Roland Schemers <schemers@stanford.edu>
Russ Allbery <rra@stanford.edu>
Jon Robertson <jonrober@stanford.edu>

=head1 SEE ALSO

L<WebKDC>
L<WebAuth>.

=cut
