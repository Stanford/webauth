package WebKDC; 

use strict;
use warnings;
use UNIVERSAL qw(isa);

#FIXME: fix these
use lib '../bindings/perl/WebAuth/blib/lib';
use lib '../bindings/perl/WebAuth/blib/arch/auto/WebAuth';

use WebAuth qw(:base64 :krb5 :const);
use WebKDC::WebRequest;
use WebKDC::WebResponse;
use WebKDC::WebKDCException;
use WebKDC::ProtocolException;
use WebKDC::Token;


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

# exported package globals go here
our $C_WEBKDC_K5SERVICE = "webauth";
our $C_WEBKDC_HOST = "lichen.stanford.edu";
our $C_SERVICE_TOKEN_LIFETIME = 3600*10; # ten hours
our $C_TOKEN_TTL = 300; # 5 minutes

# non-exported package globals go here
our $C_WEBKDC_KEYRING_PATH = "webkdc.keyring";
our $C_WEBKDC_KEYTAB = "lichen_webauth.keytab";

our $our_keyring = undef;

sub get_keyring {
    if (!defined($our_keyring)) {
	$our_keyring = WebAuth::keyring_read_file($C_WEBKDC_KEYRING_PATH);
    }
    return $our_keyring;
}

# construct a service token given:
#    $request    from krb5_mk_req (binary)
# returns:
#    $token (b64)
#    $session_key (binary)
#    $expiration_time
#    

sub make_service_token_from_krb5_cred($) {
    my $request = shift;

    # verify request first
    my $c = krb5_new();

    my $clientprinc = krb5_rd_req($c, $request, $C_WEBKDC_KEYTAB);

    my $session_key = WebAuth::random_key(WA_AES_128);
    my $creation_time = time;
    my $expiration_time = $creation_time+$C_SERVICE_TOKEN_LIFETIME;

    my $service_token = new WebKDC::WebKDCServiceToken;

    $service_token->session_key($session_key);
    $service_token->subject("krb5:$clientprinc");
    $service_token->creation_time($creation_time);
    $service_token->expiration_time($expiration_time);

    print $service_token;
    return (base64_encode($service_token->to_token(get_keyring())), 
	    $session_key, $expiration_time);
}

#

sub handle_id_request {
    my ($wreq, $wresp, $service_token, $req_token, $key) = @_;

    my $server_principal = $service_token->subject();

    my ($user,$pass) = ($wreq->user(), $wreq->pass());
    my $proxy_token_str;

    my ($et, $sad);

    if (defined($user)) { 	
	# attempt login via user/pass
	my $prd;

	my $c = krb5_new();

	eval {
	    krb5_init_via_password($c, $user, $pass, $C_WEBKDC_KEYTAB);
	};

	if (WebKDC::WebKDCException::match($@, WA_ERR_LOGIN_FAILED)) {
	    die new WebKDC::WebKDCException(WK_ERR_LOGIN_FAILED,
				      "krb5_init_via_password", $@);
	} elsif ($@) {
	    die $@;
	}

	my $cp = krb5_get_principal($c);

	# now get subject authenticator
	$server_principal =~ s/^krb5://;
	$sad = krb5_mk_req($c, $server_principal);

	# now get proxy data
	($prd, $et) = krb5_export_tgt($c);

	# save proxy token
	my $webkdc_princ = 
	    krb5_service_principal(krb5_new(),
				   $WebKDC::C_WEBKDC_K5SERVICE,
				   $WebKDC::C_WEBKDC_HOST);
	my $proxy_token = new WebKDC::WebKDCProxyToken;
	$proxy_token->proxy_owner("krb5:$webkdc_princ");
	$proxy_token->proxy_type('krb5');
	$proxy_token->proxy_data($prd);
	$proxy_token->subject("krb5:$cp");
	$proxy_token->creation_time(time());
	$proxy_token->expiration_time($et);
	print $proxy_token;
	my $proxy_token_str = 
	    base64_encode($proxy_token->to_token(get_keyring()));
	$wresp->proxy_cookie('krb5', $proxy_token_str);

    } elsif ($proxy_token_str = $wreq->proxy_cookie('krb5')) {
	my $proxy_token;

	eval {
	    $proxy_token = 
		new WebKDC::WebKDCProxyToken(base64_decode($proxy_token_str),
					     get_keyring(), 0);
	};

	if (WebAuth::Exception::match($@, WA_ERR_TOKEN_EXPIRED)) {
	    # nuke expired cookie
	    $wresp->proxy_cookie('krb5', '');
	    die new WebKDC::WebKDCException(WK_ERR_USER_AND_PASS_REQUIRED,
				      "proxy_token was expired", $@);
	} elsif ($@) {
	    die $@;
	}

	if ($proxy_token->proxy_type() ne 'krb5') {
	    # nuke cookie
	    $wresp->proxy_cookie('krb5', '');
	    die new WebKDC::WebKDCException(WK_ERR_USER_AND_PASS_REQUIRED,
				      "proxy_token type(".
				      $proxy_token->proxy_type().
				      ") not krb5 ");
	}

	$et =$proxy_token->expiration_time();

	my $c = krb5_new();

	eval {
	    krb5_init_via_tgt($c, $proxy_token->proxy_data());
	};

	if (WebAuth::Exception::match($@)) {
	    # nuke bogus cookie
	    $wresp->proxy_cookie('krb5', '');
	    #FIXME: log (this shouldn't be happening)
	    die new WebKDC::WebKDCException(WK_ERR_USER_AND_PASS_REQUIRED,
                    "error using proxy_token with krb5_init_via_tgt", $@);
	} elsif ($@) {
	    die $@;
	}
	# now get subject authenticator
	$server_principal =~ s/^krb5://;
	$sad = krb5_mk_req($c, $server_principal);

    } else {
	die new WebKDC::WebKDCException(WK_ERR_USER_AND_PASS_REQUIRED,
				  "no user/pass or proxy token");
    }

    my $id_token = new WebKDC::IdToken;
    $id_token->subject_auth('krb5');
    $id_token->subject_auth_data($sad);
    $id_token->creation_time(time());
    $id_token->expiration_time($et);
    $wresp->response_token(base64_encode($id_token->to_token($key)));
    return;
}

# create an error token

sub make_error_token($$$) {
    my($ec, $em, $key) = @_;
    my $error_token = new WebKDC::ErrorToken;
    $error_token->creation_time(time());
    $error_token->error_code($ec);
    $error_token->error_message($em);
    return base64_encode($error_token->to_token($key));
}

# takes a WebKDC::WebRequest and WebKDC::WebResponse

sub process_web_request($$) {
    my ($wreq, $wresp) = @_;

    # first parse service-token to get session key

    my $st_str = base64_decode($wreq->service_token());
    my $service_token =
	new WebKDC::WebKDCServiceToken($st_str, get_keyring(), 0);

    my $server_principal = $service_token->subject();

    if ($server_principal !~ /^krb5:/) {
	die new WebKDC::WebKDCException(WK_ERR_UNRECOVERABLE_ERROR,
                    "server_principal($server_principal) not krb5");
    }

    # use session key to parse request token
    my $key = WebAuth::key_create(WA_AES_KEY, $service_token->session_key());

    my $req_token = 
	new WebKDC::RequestToken(base64_decode($wreq->request_token()), 
				 $key, $C_TOKEN_TTL);

    # add return_url and post_url if present in request-token
    $wresp->return_url($req_token->return_url());
    $wresp->post_url($req_token->post_url());

    my $rtt = $req_token->requested_token_type();
    if ($rtt eq 'id') {
	handle_id_request($wreq, $wresp, $service_token, $req_token, $key);
    } else {
	my $ec = WA_PEC_INVALID_REQUEST;
	my $em = "unsupported token type($rtt) in request";
	$wresp->response_token(make_error_token($ec, $em, $key));
    }
}

sub parse_requester_cred($) {
    my $e = shift;
    my $req_cred = {};

    my $at = $e->attrs('type');
    if ($at eq 'service') {
	$req_cred->{'type'} = $at;
	my $st_str = $e->content;
	$st_str =~ s/^\s*(.*)\s*$/$1/;
	my $service_token =
	    new WebKDC::WebKDCServiceToken(base64_decode($st_str),
					   get_keyring(), 0);
	$req_cred->{'token'} = $service_token;
	$req_cred->{'subject'} = $service_token->subject;
	return $req_cred;
    } elsif ($at eq 'krb5') {
	$req_cred->{'type'} = $at;
	my $kreq = $e->content;
	$kreq =~ s/^\s*(.*)\s*$/$1/;
	my $princ = krb5_rd_req(krb5_new(), base64_decode($kreq), 
				$C_WEBKDC_KEYTAB);
	$req_cred->{'subject'} = "krb5:$princ";
	return $req_cred;
    } else {
	die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
			"unknown requesterCredential type($at)");
    }
}

sub parse_subject_cred($) {
    my $e = shift;
    my $sub_cred = {};

    my $at = $e->attrs('type');
    if ($at eq 'proxy') {
	$sub_cred->{'type'} = $at;
	my $pt_str = $e->content;
	$pt_str =~ s/^\s*(.*)\s*$/$1/;
	my $proxy_token =
	    new WebKDC::WebKDCProxy(base64_decode($pt_str), get_keyring(), 0);
	$sub_cred->{'token'} = $proxy_token;
	return $sub_cred;
    } else {
	die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
			"unknown subjectCredential type($at)");
    }
}

# take as input the XmlDoc representing the GetTokensRequest and
# return the XmlDoc representing the {GetTokens/Error}Response

sub process_get_tokens($) {
    my $req = shift;

    my $resp = new WebKDC::XmlDoc;

    my ($tokens,$req_cred, $sub_cred);

    foreach my $child (@{$req->children}) {
	my $name = $child-->name();
	if ($name eq 'requesterCredential') {
	    $req_cred = parse_requester_cred($child);
	} elsif ($name eq 'subjectCredential') {
	    $sub_cred = parse_subject_cred($child);
	} elsif ($name eq 'tokens') {
	    $tokens = $child;
	} else {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
			"invalid element in getTokensRequest: $name");
	}
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
    WebKDC::process_web_request($req, $resp);
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

=process_web_request(req,resp)

  WebKDC::process_web_request($req, $resp);

Used to process an incoming request token. It should be used in the
following fashion:

  my $req = new WebKDC::WebRequest;
  my $resp = new WebKDC::WebResponse;

  # if the user just submitted their username/password, include them
  if ($username && $password) {
    $req->user($username);
    $req->pass($password);
  }

  # pass in any proxy-tokens we have from a cookies
  # i.e., enumerate through all cookies that start with webauth_pt
  # and put them into a hash:
  # $cookies = { "webauth_pt_krb5" => $cookie_value }
   
  $req->proxy_cookies($cookies);

  # $req_token_str and $service_token_str would normally get
  # passed in via query/post parameters

  $req->request_token($req_token_str);
  $req->service_token($service_token_str);

  eval {
    WebLDC::process_web_request($req, $resp);
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
    # $resp->return_url  will have the return_url for a redirect
    # FIXME: check post_url first?

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
