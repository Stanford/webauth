package WebKDC; 

use strict;
use warnings;
use UNIVERSAL qw(isa);

#use blib '../bindings/perl/WebAuth';

use LWP::UserAgent;

use WebAuth qw(:base64 :krb5 :const);
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
    $VERSION     = 1.00;
    @ISA         = qw(Exporter);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;

#
# all the $C_ variables are candidates for a config file
# when one exists.
#
our $C_WEBKDC_KEYRING_PATH = "/usr/local/apache2/conf/webkdc/keyring";
our $C_WEBKDC_URL = "https://lichen.stanford.edu:8443/webkdc-service/";
#our $C_WEBKDC_URL = "http://lichen.stanford.edu:8080/webkdc-service/";

our $DEBUG = 1;

our $our_keyring = undef;

our %pec_mapping = (
	     &WA_PEC_SERVICE_TOKEN_EXPIRED => WK_ERR_UNRECOVERABLE_ERROR,
	     &WA_PEC_SERVICE_TOKEN_INVALID => WK_ERR_UNRECOVERABLE_ERROR,
	     &WA_PEC_PROXY_TOKEN_EXPIRED => WK_ERR_USER_AND_PASS_REQUIRED,
	     &WA_PEC_PROXY_TOKEN_INVALID => WK_ERR_USER_AND_PASS_REQUIRED,
	     &WA_PEC_INVALID_REQUEST => WK_ERR_UNRECOVERABLE_ERROR,
	     &WA_PEC_UNAUTHORIZED => WK_ERR_UNRECOVERABLE_ERROR,
	     &WA_PEC_SERVER_FAILURE => WK_ERR_UNRECOVERABLE_ERROR,
	     &WA_PEC_REQUEST_TOKEN_STALE => WK_ERR_UNRECOVERABLE_ERROR,
	     &WA_PEC_REQUEST_TOKEN_INVALID => WK_ERR_UNRECOVERABLE_ERROR,
	     &WA_PEC_GET_CRED_FAILURE => WK_ERR_UNRECOVERABLE_ERROR,
	     &WA_PEC_REQUESTER_KRB5_CRED_INVALID => WK_ERR_UNRECOVERABLE_ERROR,
	     &WA_PEC_LOGIN_TOKEN_STALE  => WK_ERR_USER_AND_PASS_REQUIRED,
	     &WA_PEC_LOGIN_TOKEN_INVALID => WK_ERR_USER_AND_PASS_REQUIRED,
	     &WA_PEC_LOGIN_FAILED  => WK_ERR_LOGIN_FAILED,
	     &WA_PEC_PROXY_TOKEN_REQUIRED  => WK_ERR_USER_AND_PASS_REQUIRED,
	     # LOGIN_CANCELED SHOULD NEVER COME BACK in an errorCode,
             # only inside a token which we can't decrypt
	     &WA_PEC_LOGIN_CANCELED  =>  WK_ERR_UNRECOVERABLE_ERROR,
	     &WA_PEC_LOGIN_FORCED  => WK_ERR_USER_AND_PASS_REQUIRED,
	     );

sub get_keyring {
    if (!defined($our_keyring)) {
	$our_keyring = WebAuth::keyring_read_file($C_WEBKDC_KEYRING_PATH);
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

# takes a WebKDC::WebRequest and WebKDC::WebResponse

sub request_token_request($$) {
    my ($wreq, $wresp) = @_;

    my ($user, $pass) = ($wreq->user(), $wreq->pass());
    my $request_token = $wreq->request_token();
    my $service_token = $wreq->service_token();
    my $proxy_cookies = $wreq->proxy_cookies();

    my $webkdc_doc = new WebKDC::XmlDoc;
    my $root;

    $webkdc_doc->start('requestTokenRequest');
    $webkdc_doc->start('requesterCredential', 
		       {'type' => 'service'},
		       $service_token)->end;
    $webkdc_doc->start('subjectCredential');

    if (defined($user)) {
	# need to make a login token
	$webkdc_doc->current->attr('type','login');

	my $login_token = new WebKDC::LoginToken;
	$login_token->password($pass);
	$login_token->username($user);
	$login_token->creation_time(time());

	# FIXME: DEBUGGING!
	print STDERR $login_token;

	my $login_token_str = 
	    base64_encode($login_token->to_token(get_keyring()));

	$webkdc_doc->start('loginToken',  undef, $login_token_str)->end;

    } elsif (defined($proxy_cookies)) {
	$webkdc_doc->current->attr('type','proxy');
	while (my($type,$token) = each(%{$proxy_cookies})) {
	    $webkdc_doc->start('proxyToken',  undef, $token)->end;
	}
    } else {
	# we used to short-circuit here and just raise
	# WK_ER_USER_AND_PASS_REQUIRED, but now we make a call
	# to potentially get back a login-canceled token.
	# we use subjectCredential of type proxy with no proxy tokens.
	# further note: its probably also better to go to the WebKDC
	# as we'll validate the request-token too the first time around...
	$webkdc_doc->current->attr('type','proxy');
    }
    $webkdc_doc->end('subjectCredential');
    $webkdc_doc->start('requestToken',  undef, $request_token)->end;
    $webkdc_doc->end('requestTokenRequest');

    # send the request to the webkdc

    my $xml = $webkdc_doc->root->to_string(1);
    print STDERR "-------- generated --------\n";
    print STDERR "$xml\n";
    print STDERR "-------- generated --------\n";


    my $ua = new LWP::UserAgent;

    my $http_req = new HTTP::Request(POST=> $C_WEBKDC_URL);
    $http_req->content_type('text/xml');
    $http_req->content($webkdc_doc->root->to_string());

    my $http_res = $ua->request($http_req);
    
    if (!$http_res->is_success) {
	# FIXME: get more details out of $http_res
	print STDERR "post failed\n";
	print STDERR $http_res->content;
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

    print STDERR $http_res->content;

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
	my $returned_token = get_child_value($root, 'requestedToken', 1);
	my $app_state = get_child_value($root, 'appState', 1);
	my $login_canceled_token = get_child_value($root, 'loginCanceledToken',
						   1);
	my $proxy_tokens = $root->find_child('proxyTokens');
	my $error_code = get_child_value($root, 'loginErrorCode', 1);
	my $error_message = get_child_value($root, 'loginErrorMessage', 1);

	if (defined($proxy_tokens)) {
	    foreach my $token (@{$proxy_tokens->children}) {
		my $type = $token->attr('type');
		$wresp->proxy_cookie("webauth_wpt_$type", $token->content);
	    }
	}
	$wresp->return_url($return_url);
	$wresp->response_token($returned_token);
	$wresp->requester_subject($requester_sub);
	$wresp->app_state($app_state) if defined($app_state);
	$wresp->login_canceled_token($login_canceled_token) 
	    if defined($login_canceled_token);

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
  use WebKDC::WebRequest;
  use WebKDC::WebResponse;

  eval {
    ...
    WebKDC::request_token_request($req, $resp);
    ...
  };

  if (WebKDC::WebKDCException:match($@)) {
     # handle WebKDC exceptions
  } elseif (WebAuth::Exception:match($@)) {
     # handle WebAuth exceptions
  } elsif ($@) {
     # handle other exceptions
  }

=head1 DESCRIPTION

WebKDC is a set of convenience functions built on top of mod WebAuth
to implement the WebKDC.

All functions have the potential to throw either a WebKDC::WebKDCException
or WebAuth::Exception.

=head1 EXPORT

None

=head1 FUNCTIONS

=over 4

=request_token_request(req,resp)

  WebKDC::request_token_request($req, $resp);

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

  eval {
    WebKDC::request_token_request($req, $resp);
  };

  if (WebKDC::WebKDCException::match($@, WK_ERR_LOGIN_FAILED)) {
   # need to prompt again, also need to limit number of times
    # we'll prompt
    # make sure to pass the request/service tokens in hidden fields

  } elsif (WebKDC::WebKDCException::match($@, WK_ERR_USER_AND_PASS_REQUIRED)) {

    # this exception indicates someone requested an id-token
    # and either didn't have a proxy-token, or it was expired.
    # prompt the user for their username/password, making sure
    # to pass the request/service tokens in hidden fields
    
    # also need to check $resp->proxy_cookies() to see if we have
    # to update any proxy cookies

  } elsif ($@) {
    
    # something nasty happened
    # log $@, and display an error to the user that a system problem
    # has occurred and tell them to try again later

    # also need to check $resp->proxy_cookies() to see if we have
    # to update any proxy cookies

  } else {

    # everything went ok
    # $resp->return_url  will have the return_url for a redirect/confirm

    # also need to check $resp->proxy_cookies() to see if we have
    # to update any proxy cookies

  }

=head1 AUTHOR

Roland Schemers (schemers@stanford.edu)

=head1 SEE ALSO

L<WebKDC::WebKDCException>
L<WebKDC::Token>
L<WebKDC::WebRequest>
L<WebKDC::WebRespsonse>
L<WebAuth>.

=cut
