# Interact with the WebAuth WebKDC service.
#
# Written by Roland Schemers
# Copyright 2002, 2003, 2004, 2005, 2006, 2008, 2009, 2011
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebKDC;

use strict;
use warnings;

use LWP::UserAgent;

use WebAuth qw(:base64 :krb5 :const);
use WebKDC::Config;
use WebKDC::WebRequest;
use WebKDC::WebResponse;
use WebKDC::WebKDCException;
use WebKDC::Token;
use WebKDC::XmlDoc;
use WebKDC::XmlElement;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.02;
    @ISA         = qw(Exporter);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;

our $DEBUG = 1;

our $our_keyring = undef;

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
);

sub get_keyring {
    if (!defined($our_keyring)) {
	$our_keyring =
            WebAuth::Keyring->read_file($WebKDC::Config::KEYRING_PATH);
    }
    return $our_keyring;
}

sub get_child_value {
    my ($e, $name, $opt) = @_;

    my $child = $e->find_child($name);
    if (!defined($child)) {
	return undef if $opt;
	die new WebKDC::WebKDCException(WK_ERR_UNRECOVERABLE_ERROR,
					"webkdc response missing: <$name>");
    } else {
	return $child->content;
    }
}

# Takes the Kerberos V5 request and the exported TGT and makes a
# <webkdcProxyTokenRequest> call.  A wrapper around proxy_token_request, which
# does the actual work.  This just handles exceptions.
sub make_proxy_token_request($$) {
    my ($req, $tgt) = @_;

    my ($token, $subject);
    eval {
        ($token, $subject) = WebKDC::proxy_token_request($req, $tgt);
    };

    my $e = $@;
    if (ref $e and $e->isa('WebKDC::WebKDCException')) {
        return ($e->status(), $e);
    } elsif ($e) {
        return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $e);
    } else {
        return (WebKDC::WK_SUCCESS, undef, $token, $subject);
    }
}

# takes a WebKDC::WebRequest and WebKDC::WebResponse
sub make_request_token_request($$) {
    my ($req, $resp) = @_;

    eval {
	WebKDC::request_token_request($req, $resp);
      };

    my $e = $@;

    if (ref $e and $e->isa("WebKDC::WebKDCException")) {
	return ($e->status(), $e);
    } elsif ($e) {
	return (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, $e);
    } else {
	return (WebKDC::WK_SUCCESS, undef);
    }
}

# Takes the Kerberos V5 request and the exported TGT and makes a
# <webkdcProxyTokenRequest> call.  Throws an exception on failure.
sub proxy_token_request($$) {
    my ($req, $tgt) = @_;

    # Build the XML request.
    my $webkdc_doc = new WebKDC::XmlDoc;
    $webkdc_doc->start('webkdcProxyTokenRequest');
    $webkdc_doc->start('subjectCredential', {'type' => 'krb5'}, $req)->end;
    $webkdc_doc->start('proxyData', undef, $tgt)->end;
    $webkdc_doc->end('webkdcProxyTokenRequest');

    # Send the request to the WebKDC.
    my $ua = new LWP::UserAgent;
    my $http_req = new HTTP::Request(POST => $WebKDC::Config::URL);
    $http_req->content_type('text/xml');
    $http_req->content($webkdc_doc->root->to_string());

    # Get the response.
    my $http_res = $ua->request($http_req);
    if (!$http_res->is_success) {
        # FIXME: Better error reporting needed here.
        print STDERR "post failed\n";
        print STDERR $http_res->as_string . "\n";
        print STDERR $http_res->content . "\n";
        die new WebKDC::WebKDCException(WK_ERR_UNRECOVERABLE_ERROR,
                                        "post to webkdc failed");
    }
    my $root;
    eval {
        $root = new WebKDC::XmlElement($http_res->content);
    };
    if ($@) {
	my $msg = "unable to parse response from webkdc: $@";
	print STDERR "$msg ".$http_res->content."\n";
	die new WebKDC::WebKDCException(WK_ERR_UNRECOVERABLE_ERROR, $msg);
    }
    if ($root->name() eq 'errorResponse') {
	my $error_code = get_child_value($root, 'errorCode', 1);
	my $error_message = get_child_value($root, 'errorMessage', 0);
	my $wk_err = $pec_mapping{$error_code} || WK_ERR_UNRECOVERABLE_ERROR;
	die new WebKDC::WebKDCException($wk_err,
					"WebKDC error: $error_message ".
					"($error_code)", $error_code);
    } elsif ($root->name eq 'webkdcProxyTokenResponse') {
        my $token = get_child_value($root, 'webkdcProxyToken', 0);
        my $subject = get_child_value($root, 'subject', 0);
        return ($token, $subject);
    } else {
        die new WebKDC::WebKDCException(WK_ERR_UNRECOVERABLE_ERROR,
                                        "unknown response from WebKDC: "
                                        . $root->name);
    }
}

# takes a WebKDC::WebRequest and WebKDC::WebResponse
sub request_token_request($$) {
    my ($wreq, $wresp) = @_;

    my ($user, $pass, $otp) = ($wreq->user(), $wreq->pass(), $wreq->otp());
    my $request_token = $wreq->request_token();
    my $service_token = $wreq->service_token();
    my $proxy_cookies = $wreq->proxy_cookies_rich();

    my $webkdc_doc = new WebKDC::XmlDoc;
    my $root;

    $webkdc_doc->start('requestTokenRequest');
    $webkdc_doc->start('requesterCredential',
		       {'type' => 'service'},
		       $service_token)->end;
    $webkdc_doc->start('subjectCredential');

    # Create any login or proxy tokens for the user.  If there are none, we
    # used to short-circuit here and raise WK_ER_USER_AND_PASS_REQUIRED, but
    # now we go ahead with tokens to potentially get back a login-canceled
    # token.  further note: its probably also better to go to the WebKDC as
    # we'll validate the request-token too the first time around...
    if (defined($user) || defined($proxy_cookies)) {

        if (defined($user)) {
            my $login_token = new WebKDC::LoginToken;
            $login_token->username($user);
            $login_token->creation_time(time());
            if (defined $otp) {
                $login_token->otp($otp);
            } else {
                $login_token->password($pass);
            }

            my $login_token_str =
                base64_encode($login_token->to_token(get_keyring()));

            $webkdc_doc->start('loginToken', undef, $login_token_str)->end;
        }

        if (defined($proxy_cookies)) {
            $webkdc_doc->current->attr('type','proxy');
            for my $type (keys %$proxy_cookies) {
                my $token = $proxy_cookies->{$type}{'cookie'};
                my $source = $proxy_cookies->{$type}{'session_factor'};
                $webkdc_doc->start('proxyToken',
                                   {'type' => $type, 'source' => $source},
                                   $token)->end;
            }
        }

	# FIXME: DEBUGGING!
	#print STDERR $login_token;
    }

    $webkdc_doc->end('subjectCredential');
    $webkdc_doc->start('requestToken',  undef, $request_token)->end;
    if ($wreq->local_ip_addr() || $wreq->remote_user()) {
	$webkdc_doc->start('requestInfo');
        if ($wreq->local_ip_addr()) {
            $webkdc_doc->add('localIpAddr', undef, $wreq->local_ip_addr());
            $webkdc_doc->add('localIpPort', undef, $wreq->local_ip_port());
            $webkdc_doc->add('remoteIpAddr', undef, $wreq->remote_ip_addr());
            $webkdc_doc->add('remoteIpPort', undef, $wreq->remote_ip_port());
        }
        if ($wreq->remote_user()) {
            $webkdc_doc->add('remoteUser', undef, $wreq->remote_user());
        }
	$webkdc_doc->end('requestInfo');
    }
    $webkdc_doc->end('requestTokenRequest');

    # send the request to the webkdc

    my $xml = $webkdc_doc->root->to_string(1);
    #print STDERR "-------- generated --------\n";
    #print STDERR "$xml\n";
    #print STDERR "-------- generated --------\n";


    my $ua = new LWP::UserAgent;

    my $http_req = new HTTP::Request(POST=> $WebKDC::Config::URL);
    $http_req->content_type('text/xml');
    $http_req->content($webkdc_doc->root->to_string());

    my $http_res = $ua->request($http_req);

    if (!$http_res->is_success) {
	# FIXME: get more details out of $http_res
	print STDERR "post failed\n";
	print STDERR $http_res->as_string."\n";
	print STDERR $http_res->content."\n";
	die new WebKDC::WebKDCException(WK_ERR_UNRECOVERABLE_ERROR,
					"post to webkdc failed");
    }

    eval {
	$root = new WebKDC::XmlElement($http_res->content);
    };
    if ($@) {
	my $msg = "unable to parse response from webkdc: $@";
	print STDERR "$msg ".$http_res->content."\n";
	die new WebKDC::WebKDCException(WK_ERR_UNRECOVERABLE_ERROR, $msg);
    }

    #print STDERR $http_res->content;

    if ($root->name() eq 'errorResponse') {
	my $error_code = get_child_value($root, 'errorCode', 1);
	my $error_message = get_child_value($root, 'errorMessage', 0);
	my $wk_err = $pec_mapping{$error_code} || WK_ERR_UNRECOVERABLE_ERROR;

	# dump any existing proxy-tokens if we are logging in
	if ($wk_err == WK_ERR_USER_AND_PASS_REQUIRED) {
	    my $proxy_cookies = $wreq->proxy_cookies();
	    if (defined($proxy_cookies)) {
		while (my($name,$token) = each(%{$proxy_cookies})) {
		    $wresp->proxy_cookie($name, '');
		}
	    }
	}
	die new WebKDC::WebKDCException($wk_err,
					"WebKDC error: $error_message ".
					"($error_code)", $error_code);

    } elsif ($root->name() eq 'requestTokenResponse') {
	my $return_url = get_child_value($root, 'returnUrl', 0);
	my $requester_sub = get_child_value($root, 'requesterSubject', 0);
	my $subject = get_child_value($root, 'subject', 1);
	my $returned_token = get_child_value($root, 'requestedToken', 1);
	my $returned_token_type = get_child_value($root, 'requestedTokenType',
						  1);
	my $app_state = get_child_value($root, 'appState', 1);
	my $login_canceled_token = get_child_value($root, 'loginCanceledToken',
						   1);
	my $proxy_tokens = $root->find_child('proxyTokens');
	my $error_code = get_child_value($root, 'loginErrorCode', 1);
	my $error_message = get_child_value($root, 'loginErrorMessage', 1);

	if (defined($proxy_tokens)) {
	    foreach my $token (@{$proxy_tokens->children}) {
		my $type = $token->attr('type');
		my $cname = "webauth_wpt_$type";
		my $cvalue  = $token->content || '';
		$wresp->proxy_cookie($cname, $cvalue);
	    }
	}

        my $multifactor = $root->find_child('multifactorRequired');
        if (defined($multifactor)) {
            foreach my $mf_setting (@{$multifactor->children}) {
                my $factor = $mf_setting->content;
                if ($mf_setting->name eq 'factor') {
                    $wresp->factor_needed($factor);
                } elsif ($mf_setting->name eq 'configuredFactor') {
                    $wresp->factor_configured($factor);
                }
            }
        }

        my $login_history = $root->find_child('loginHistory');
        if (defined($login_history)) {
            foreach my $login (@{$login_history->children}) {
                my $timestamp = $login->attr('time');
                my $ip = $login->attr('ip');
                my $hostname = $login->content | '';
                $wresp->login_history ([$timestamp, $ip, $hostname]);
            }
        }

        $wresp->return_url($return_url);
	$wresp->response_token($returned_token);
	$wresp->response_token_type($returned_token_type);
	$wresp->requester_subject($requester_sub);
	$wresp->app_state($app_state) if defined($app_state);
	$wresp->login_canceled_token($login_canceled_token)
	    if defined($login_canceled_token);
	$wresp->subject($subject) if defined($subject);

	if ($error_code) {
	    my $wk_err = $pec_mapping{$error_code} ||
		WK_ERR_UNRECOVERABLE_ERROR;
	    die new WebKDC::WebKDCException($wk_err,
					    "Login error: $error_message ".
					    "($error_code)", $error_code);
	}
	return;
    } else {
	die new WebKDC::WebKDCException(WK_ERR_UNRECOVERABLE_ERROR,
					"unknown response from WebKDC: ".
					$root->name());
    }
}

END { }       # module clean-up code here (global destructor)

1;

__END__

=head1 NAME

WebKDC - functions to support the WebKDC

=head1 SYNOPSIS

  use WebAuth;
  use WebKDC;
  use WebKDC::Exception;
  use WebKDC::WebRequest;
  use WebKDC::WebResponse;

  my ($status, $exception) =
         WebKDC::make_request_token_request($req, $resp);

=head1 DESCRIPTION

WebKDC is a set of convenience functions built on top of mod WebAuth
to implement the WebKDC.

All functions have the potential to throw either a WebKDC::WebKDCException
or WebAuth::Exception.

=head1 EXPORT

None

=head1 FUNCTIONS

=over 4

=item make_request_token_request(req,resp)

  ($status, $e) = WebKDC::make_request_token_request($req, $resp);

Used to handle an incoming request token. It should be used in the
following fashion:

  my $req = new WebKDC::WebRequest;
  my $resp = new WebKDC::WebResponse;

  # if the user just submitted their username/password, include them
  if ($username && $password) {
    $req->user($username);
    $req->pass($password);
  }

  # pass in any proxy-tokens we have from a cookies
  # i.e., enumerate through all cookies that start with webauth_wpt
  # and put them into a hash:
  # $cookies = { "webauth_wpt_krb5" => $cookie_value }

  $req->proxy_cookies($cookies);

  # $req_token_str and $service_token_str would normally get
  # passed in via query/post parameters

  $req->request_token($req_token_str);
  $req->service_token($service_token_str);

  my ($status, $e) = WebKDC::make_request_token_request($req, $resp);

  # for all these cases, check if $resp->proxy_cookies() has any
  # proxy cookies we need to update when sending back a page to
  # the browser

  if ($status == WK_SUCCESS) {
     # ok, request successful
  } elsif ($status == WK_ERR_USER_AND_PASS_REQUIRED
           || $status == WK_LOGIN_FORCED) {
     # prompt for user/pass
  } elsif ($status == WK_ERR_LOGIN_FAILED) {
     # supplied user/pass was invalid, try again
  } else {
    # use this if/elsif/else to pick the error message
    if ($status == WK_ERR_UNRECOVERABLE_ERROR) {
       # something nasty happened.
    } elsif ($status == WK_ERR_REQUEST_TOKEN_STATLE) {
       # user took too long to login, original request token is stale
    } elsif ($status == WK_ERR_WEBAUTH_SERVER_ERROR) {
       # like WK_ERR_UNRECOVERABLE_ERROR, but indicates the error
       # most likely is due to the webauth server making the request,
    } else {
       # treat like WK_ERROR_UNRECOVERABLE ERROR
    }
    # display the error message and don't prompt anymore
  }

=back

=head1 AUTHOR

Roland Schemers (schemers@stanford.edu)

=head1 SEE ALSO

L<WebKDC::WebKDCException>
L<WebKDC::Token>
L<WebKDC::WebRequest>
L<WebKDC::WebRespsonse>
L<WebAuth>.

=cut
