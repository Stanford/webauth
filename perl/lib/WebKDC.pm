# Interact with the WebAuth WebKDC service.
#
# Written by Roland Schemers
# Copyright 2002, 2003, 2004, 2005, 2006, 2008, 2009, 2011, 2012
#     The Board of Trustees of the Leland Stanford Junior University
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

package WebKDC;

use 5.006;
use strict;
use warnings;

use LWP::UserAgent;

use WebAuth qw(3.00 :const);
use WebAuth::Keyring ();
use WebKDC::Config;
use WebKDC::WebRequest 1.02;
use WebKDC::WebResponse 1.02;
use WebKDC::WebKDCException 1.05;
use WebKDC::XmlDoc;
use WebKDC::XmlElement;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION;
BEGIN {
    $VERSION = '2.05';
}

# Map protocol error codes to the error codes that we're going to use internal
# to the WebLogin code and other WebKDC::* modules.
our %pec_mapping = (
    &WA_PEC_SERVICE_TOKEN_EXPIRED       => WK_ERR_WEBAUTH_SERVER_ERROR,
    &WA_PEC_SERVICE_TOKEN_INVALID       => WK_ERR_WEBAUTH_SERVER_ERROR,
    &WA_PEC_PROXY_TOKEN_EXPIRED         => WK_ERR_USER_AND_PASS_REQUIRED,
    &WA_PEC_PROXY_TOKEN_INVALID         => WK_ERR_USER_AND_PASS_REQUIRED,
    &WA_PEC_INVALID_REQUEST             => WK_ERR_UNRECOVERABLE_ERROR,
    &WA_PEC_UNAUTHORIZED                => WK_ERR_WEBAUTH_SERVER_ERROR,
    &WA_PEC_SERVER_FAILURE              => WK_ERR_UNRECOVERABLE_ERROR,
    &WA_PEC_REQUEST_TOKEN_STALE         => WK_ERR_REQUEST_TOKEN_STALE,
    &WA_PEC_REQUEST_TOKEN_INVALID       => WK_ERR_WEBAUTH_SERVER_ERROR,
    &WA_PEC_GET_CRED_FAILURE            => WK_ERR_UNRECOVERABLE_ERROR,
    &WA_PEC_REQUESTER_KRB5_CRED_INVALID => WK_ERR_UNRECOVERABLE_ERROR,
    &WA_PEC_LOGIN_TOKEN_STALE           => WK_ERR_USER_AND_PASS_REQUIRED,
    &WA_PEC_LOGIN_TOKEN_INVALID         => WK_ERR_USER_AND_PASS_REQUIRED,
    &WA_PEC_LOGIN_FAILED                => WK_ERR_LOGIN_FAILED,
    &WA_PEC_PROXY_TOKEN_REQUIRED        => WK_ERR_USER_AND_PASS_REQUIRED,

    # LOGIN_CANCELED SHOULD NEVER COME BACK in an errorCode, only inside a
    # token which we can't decrypt, since it's the error code that's sent
    # to the WAS in the login canceled token.
    &WA_PEC_LOGIN_CANCELED              => WK_ERR_UNRECOVERABLE_ERROR,

    &WA_PEC_LOGIN_FORCED                => WK_ERR_LOGIN_FORCED,
    &WA_PEC_USER_REJECTED               => WK_ERR_USER_REJECTED,
    &WA_PEC_CREDS_EXPIRED               => WK_ERR_CREDS_EXPIRED,
    &WA_PEC_MULTIFACTOR_REQUIRED        => WK_ERR_MULTIFACTOR_REQUIRED,
    &WA_PEC_MULTIFACTOR_UNAVAILABLE     => WK_ERR_MULTIFACTOR_UNAVAILABLE,
    &WA_PEC_LOGIN_REJECTED              => WK_ERR_LOGIN_REJECTED,
    &WA_PEC_LOA_UNAVAILABLE             => WK_ERR_LOA_UNAVAILABLE,
    &WA_PEC_AUTH_REJECTED               => WK_ERR_AUTH_REJECTED,
    &WA_PEC_REPLAY                      => WK_ERR_REPLAY,
    &WA_PEC_AUTH_RATE_LIMITED           => WK_ERR_AUTH_RATE_LIMITED,
);

# Get a keyring from the configured WebLogin keyring path.  This used to
# cache, but we have to tie the lifetime to the WebAuth context, so it's not
# easy to cache.
sub get_keyring {
    my ($wa) = @_;
    return WebAuth::Keyring->read ($wa, $WebKDC::Config::KEYRING_PATH);
}

# Throw a WebKDCException with the given error code and error message and
# optional protocol error code and data
sub throw {
    my ($code, $error, $pec, $data) = @_;
    die WebKDC::WebKDCException->new ($code, $error, $pec, $data);
}

# Get the value of the given child of an element or throw an exception if
# the child can't be found.
sub get_child_value {
    my ($e, $name, $opt) = @_;

    my $child = $e->find_child ($name);
    unless (defined $child) {
        return undef if $opt;
        throw (WK_ERR_UNRECOVERABLE_ERROR, "webkdc response missing: <$name>");
    } else {
        return $child->content;
    }
}

# Takes the Kerberos request and the exported TGT and makes a
# <webkdcProxyTokenRequest> call.  A wrapper around proxy_token_request, which
# does the actual work.  This just handles exceptions.
#
# Returns the status code, the exception (if any), the token (on success), and
# the subject (on success).
sub make_proxy_token_request {
    my ($req, $tgt) = @_;
    my ($token, $subject);
    ($token, $subject) = eval { WebKDC::proxy_token_request ($req, $tgt) };
    my $e = $@;
    if (ref $e and $e->isa ('WebKDC::WebKDCException')) {
        return ($e->status, $e);
    } elsif ($e) {
        return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $e);
    } else {
        return (WebKDC::WK_SUCCESS, undef, $token, $subject);
    }
}

# Takes a WebKDC::WebRequest and WebKDC::WebResponse.  Fills in the response
# on success.  Returns a status code and the exception as a list.
sub make_request_token_request {
    my ($req, $resp) = @_;
    eval { WebKDC::request_token_request($req, $resp) };
    my $e = $@;
    if (ref $e and $e->isa ("WebKDC::WebKDCException")) {
        return ($e->status, $e);
    } elsif ($e) {
        return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $e);
    } else {
        return (WebKDC::WK_SUCCESS, undef);
    }
}

# Takes the Kerberos request and the exported TGT and makes a
# <webkdcProxyTokenRequest> call.  Throws an exception on failure.
sub proxy_token_request {
    my ($req, $tgt) = @_;

    # Build the XML request.
    my $webkdc_doc = WebKDC::XmlDoc->new;
    $webkdc_doc->start ('webkdcProxyTokenRequest');
    $webkdc_doc->start ('subjectCredential', {'type' => 'krb5'}, $req)->end;
    $webkdc_doc->start ('proxyData', undef, $tgt)->end;
    $webkdc_doc->end ('webkdcProxyTokenRequest');

    # Send the request to the WebKDC.
    my $ua = LWP::UserAgent->new;
    my $http_req = HTTP::Request->new (POST => $WebKDC::Config::URL);
    $http_req->content_type ('text/xml');
    $http_req->content ($webkdc_doc->root->to_string);

    # Get the response.
    my $http_res = $ua->request ($http_req);
    if (!$http_res->is_success) {
        # FIXME: Better error reporting needed here.
        print STDERR "post failed\n";
        print STDERR $http_res->as_string . "\n";
        print STDERR $http_res->content . "\n";
        throw (WK_ERR_UNRECOVERABLE_ERROR, "post to webkdc failed");
    }
    my $root = eval { WebKDC::XmlElement->new ($http_res->content) };
    if ($@) {
        my $msg = "unable to parse response from webkdc: $@";
        print STDERR "$msg " . $http_res->content . "\n";
        throw (WK_ERR_UNRECOVERABLE_ERROR, $msg);
    }
    if ($root->name eq 'errorResponse') {
        my $error_code = get_child_value ($root, 'errorCode', 1);
        my $error_message = get_child_value ($root, 'errorMessage', 0);
        my $wk_err = $pec_mapping{$error_code} || WK_ERR_UNRECOVERABLE_ERROR;
        throw ($wk_err, "WebKDC error: $error_message ($error_code)",
               $error_code);
    } elsif ($root->name eq 'webkdcProxyTokenResponse') {
        my $token = get_child_value ($root, 'webkdcProxyToken', 0);
        my $subject = get_child_value ($root, 'subject', 0);
        return ($token, $subject);
    } else {
        throw (WK_ERR_UNRECOVERABLE_ERROR,
               "unknown response from WebKDC: " . $root->name);
    }
}

# Takes a WebKDC::WebRequest and WebKDC::WebResponse.  Fills in the response
# on success.  Throws an exception on failure.
sub request_token_request {
    my ($wreq, $wresp) = @_;
    my ($user, $pass, $otp) = ($wreq->user, $wreq->pass, $wreq->otp);
    my $request_token = $wreq->request_token;
    my $service_token = $wreq->service_token;
    my $proxy_cookies = $wreq->proxy_cookies_rich;

    my $webkdc_doc = WebKDC::XmlDoc->new;
    my $wa = WebAuth->new;
    my $root;

    $webkdc_doc->start ('requestTokenRequest');
    $webkdc_doc->start ('requesterCredential', {'type' => 'service'},
                        $service_token)->end;

    # Create any login or proxy tokens for the user.  If there are none, we
    # still go ahead to validate the request token and to get a login cancel
    # token, if any.
    $webkdc_doc->start ('subjectCredential');
    if (defined ($user) && (defined ($pass) || defined ($otp))) {
        my $login_token = WebAuth::Token::Login->new ($wa);
        $login_token->username ($user);
        $login_token->creation (time);
        if (defined $otp) {
            $login_token->otp ($otp);
        } else {
            $login_token->password ($pass);
        }
        my $login_token_str = $login_token->encode (get_keyring ($wa));
        $webkdc_doc->start ('loginToken', undef, $login_token_str)->end;
    }
    if (defined $proxy_cookies) {
        $webkdc_doc->current->attr ('type','proxy');
        for my $type (keys %$proxy_cookies) {
            my $token = $proxy_cookies->{$type}{'cookie'};
            my $source = $proxy_cookies->{$type}{'session_factor'};
            $webkdc_doc->start ('proxyToken',
                                {'type' => $type, 'source' => $source},
                                $token)->end;
        }
    }
    $webkdc_doc->end('subjectCredential');

    # Add the request token, authorization identity, and request information.
    $webkdc_doc->start ('requestToken', undef, $request_token)->end;
    if ($wreq->authz_subject) {
        $webkdc_doc->start ('authzSubject', undef, $wreq->authz_subject)->end;
    }
    if ($wreq->local_ip_addr || $wreq->remote_user) {
        $webkdc_doc->start('requestInfo');
        if ($wreq->local_ip_addr) {
            $webkdc_doc->add ('localIpAddr', undef, $wreq->local_ip_addr);
            $webkdc_doc->add ('localIpPort', undef, $wreq->local_ip_port);
            $webkdc_doc->add ('remoteIpAddr', undef, $wreq->remote_ip_addr);
            $webkdc_doc->add ('remoteIpPort', undef, $wreq->remote_ip_port);
        }
        if ($wreq->remote_user) {
            $webkdc_doc->add ('remoteUser', undef, $wreq->remote_user());
        }
        $webkdc_doc->end ('requestInfo');
    }
    $webkdc_doc->end ('requestTokenRequest');

    # Send the request to the webkdc
    my $xml = $webkdc_doc->root->to_string (1);
    my $ua = LWP::UserAgent->new;
    my $http_req = HTTP::Request->new (POST => $WebKDC::Config::URL);
    $http_req->content_type ('text/xml');
    $http_req->content ($webkdc_doc->root->to_string);
    my $http_res = $ua->request ($http_req);
    if (!$http_res->is_success) {
        # FIXME: get more details out of $http_res
        print STDERR "post failed\n";
        print STDERR $http_res->as_string . "\n";
        print STDERR $http_res->content . "\n";
        throw (WK_ERR_UNRECOVERABLE_ERROR, "post to webkdc failed");
    }

    # Parse the response.
    $root = eval { WebKDC::XmlElement->new ($http_res->content) };
    if ($@) {
        my $msg = "unable to parse response from webkdc: $@";
        print STDERR "$msg " . $http_res->content . "\n";
        throw (WK_ERR_UNRECOVERABLE_ERROR, $msg);
    }

    if ($root->name eq 'errorResponse') {
        my $error_code = get_child_value ($root, 'errorCode', 1);
        my $error_message = get_child_value ($root, 'errorMessage', 0);
        my $wk_err = $pec_mapping{$error_code} || WK_ERR_UNRECOVERABLE_ERROR;

        # Dump any existing webkdc-proxy tokens if we are logging in.
        if ($wk_err == WK_ERR_USER_AND_PASS_REQUIRED) {
            my $proxy_cookies = $wreq->proxy_cookies;
            if (defined $proxy_cookies) {
                while (my ($name, $token) = each %{$proxy_cookies}) {
                    $wresp->proxy_cookie ($name, '');
                }
            }
        }
        throw ($wk_err, "WebKDC error: $error_message ($error_code)",
               $error_code);

    } elsif ($root->name eq 'requestTokenResponse') {
        my $return_url = get_child_value ($root, 'returnUrl', 0);
        my $requester_sub = get_child_value ($root, 'requesterSubject', 0);
        my $subject = get_child_value ($root, 'subject', 1);
        my $authz_subject = get_child_value ($root, 'authzSubject', 1);
        my $returned_token = get_child_value ($root, 'requestedToken', 1);
        my $returned_token_type
            = get_child_value ($root, 'requestedTokenType', 1);
        my $app_state = get_child_value ($root, 'appState', 1);
        my $login_canceled_token
            = get_child_value ($root, 'loginCanceledToken', 1);
        my $proxy_tokens = $root->find_child ('proxyTokens');
        my $error_code = get_child_value ($root, 'loginErrorCode', 1);
        my $error_message = get_child_value ($root, 'loginErrorMessage', 1);
        my $user_message = get_child_value ($root, 'userMessage', 1);

        if (defined $proxy_tokens) {
            for my $token (@{ $proxy_tokens->children }) {
                my $type = $token->attr ('type');
                my $cname = "webauth_wpt_$type";
                my $cvalue  = $token->content || '';
                $wresp->proxy_cookie ($cname, $cvalue);
            }
        }

        my $multifactor = $root->find_child ('multifactorRequired');
        if (defined $multifactor) {
            for my $mf_setting (@{$multifactor->children}) {
                my $factor = $mf_setting->content;
                if ($mf_setting->name eq 'factor') {
                    $wresp->factor_needed ($factor);
                } elsif ($mf_setting->name eq 'configuredFactor') {
                    $wresp->factor_configured ($factor);
                }
            }
        }

        my $permitted_authz = $root->find_child ('permittedAuthzSubjects');
        if (defined $permitted_authz) {
            my @authz;
            for my $authz (@{ $permitted_authz->children }) {
                if ($authz->name eq 'authzSubject') {
                    push (@authz, $authz->content);
                }
            }
            $wresp->permitted_authz (@authz);
        }

        my $login_history = $root->find_child ('loginHistory');
        if (defined $login_history) {
            for my $login (@{ $login_history->children }) {
                my %hist;
                $hist{timestamp} = $login->attr ('time');
                $hist{hostname} = $login->attr ('name');
                $hist{ip} = $login->content || '';
                $wresp->login_history (\%hist);
            }
        }

        $wresp->return_url ($return_url);
        $wresp->response_token ($returned_token);
        $wresp->response_token_type ($returned_token_type);
        $wresp->requester_subject ($requester_sub);
        $wresp->app_state ($app_state) if defined $app_state;
        $wresp->login_canceled_token ($login_canceled_token)
            if defined $login_canceled_token;
        $wresp->subject ($subject) if defined $subject;
        $wresp->authz_subject ($authz_subject) if defined $authz_subject;

        if ($error_code) {
            my $wk_err = $pec_mapping{$error_code}
                || WK_ERR_UNRECOVERABLE_ERROR;
            throw ($wk_err, "Login error: $error_message ($error_code)",
                   $error_code, $user_message);
        }
        return;
    } else {
        throw (WK_ERR_UNRECOVERABLE_ERROR,
               "unknown response from WebKDC: " . $root->name);
    }
}

1;

__END__

=for stopwords
WebAuth webkdc-proxy authenticator WebKDC WebKDC's WebLogin AUTH TGT
Allbery

=head1 NAME

WebKDC - Send requests to a WebAuth WebKDC

=head1 SYNOPSIS

    use WebKDC;
    use WebKDC::Exception;
    use WebKDC::WebRequest;
    use WebKDC::WebResponse;

    my ($status, $exception)
        = WebKDC::make_request_token_request ($req, $resp);
    my ($token, $subject);
    ($status, $exception, $token, $subject)
        = WebKDC::make_proxy_token_request ($krbreq, $tgt);

=head1 DESCRIPTION

This module provides functions to make a <requestToken> and a
<webkdcProxyToken> call to a WebAuth WebKDC.  These functions encapsulate
the XML protocol and HTTP requests.  This module is primarily intended for
use by the WebLogin server to process requests from WebAuth Application
Servers.

=head1 FUNCTIONS

=over 4

=item make_proxy_token_request (AUTH, TGT)

Makes a <webkdcProxyToken> request to the WebKDC.  The result, if
successful, will be a webkdc-proxy token that can be passed into a
subsequent call to make_request_token_request.

AUTH is a Kerberos authenticator for the WebKDC's Kerberos principal, as
generated by the WebAuth::Krb5 make_auth method.  TGT is a Kerberos
ticket-granting ticket, exported with the WebAuth::Krb5 export_cred
method, and then encrypted in the same call to make_auth as the DATA
argument.  Both must already be base64-encoded.

The return value is a four-element list.  The first value will be the
status.  On error, the second value is an exception object and the
remaining values are undef.  On success, the second value is undef, the
third value is the webkdc-proxy token (base64-encoded), and the fourth
value is the subject (the identity) represented by the webkdc-proxy token.

=item make_request_token_request (REQUEST, RESPONSE)

Used to handle an incoming request token.  REQUEST is a populated
WebKDC::WebRequest object, and RESPONSE should be a newly-created
WebKDC::WebResponse object.  The request will be handled off to the
configured WebKDC (see L<WebKDC::Config>) and the results stored in the
response object.

The return value is a list of the status and the exception object, if any.
The status will be WK_SUCCESS on success and some other WK_ERR_* status
code on failure.  See L<WebKDC::WebKDCException> for the other status
codes.

=back

=head1 AUTHOR

Roland Schemers and Russ Allbery <rra@stanford.edu>.

=head1 SEE ALSO

WebAuth(3), WebAuth::Krb5(3), WebKDC::WebKDCException(3),
WebKDC::WebRequest(3), WebKDC::WebRespsonse(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
