package WebKDC; 

use strict;
use warnings;
use UNIVERSAL qw(isa);

#use blib '../bindings/perl/WebAuth';

use WebAuth qw(:base64 :krb5 :const);
use WebKDC::WebRequest;
use WebKDC::WebResponse;
use WebKDC::WebKDCException;
use WebKDC::ProtocolException;
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

# exported package globals go here
our $C_WEBKDC_K5SERVICE = "webauth";
our $C_WEBKDC_HOST = "lichen.stanford.edu";
our $C_SERVICE_TOKEN_LIFETIME = 3600*10; # ten hours
our $C_TOKEN_TTL = 300; # 5 minutes

# non-exported package globals go here
our $C_WEBKDC_KEYRING_PATH = "webkdc.keyring";
our $C_WEBKDC_KEYTAB = "lichen_webauth.keytab";

our $DEBUG = 1;


our $our_keyring = undef;

sub get_keyring {
    if (!defined($our_keyring)) {
	$our_keyring = WebAuth::keyring_read_file($C_WEBKDC_KEYRING_PATH);
    }
    return $our_keyring;
}

#
# given 
#

sub create_errorResponse($$) {
    my ($ec, $em) = @_;

    my $doc = new WebKDC::XmlDoc;
    $doc->start("errorResponse");
    $doc->start("errorCode", undef, $ec)->end;
    $doc->start("errorMessage", undef, $em)->end;
    $doc->end;
    return $doc->root();
}

# construct a service token given:
#    $request    from krb5_mk_req (binary)
# returns:
#    $token (b64)
#    $session_key (binary)
#    $expiration_time
#    
#
# FIXME: this is for testing

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

    #print $service_token;
    return (base64_encode($service_token->to_token(get_keyring())), 
	    $session_key, $expiration_time);
}

#

sub handle_web_id_request {
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

	if (WebAuth::Exception::match($@, WA_ERR_LOGIN_FAILED)) {
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
	$proxy_token->proxy_subject("krb5:$webkdc_princ");
	$proxy_token->proxy_type('krb5');
	$proxy_token->proxy_data($prd);
	$proxy_token->subject("krb5:$cp");
	$proxy_token->creation_time(time());
	$proxy_token->expiration_time($et);
	#print $proxy_token;
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

sub create_error_token($$$) {
    my($ec, $em, $key) = @_;
    my $error_token = new WebKDC::ErrorToken;
    $error_token->creation_time(time());
    $error_token->error_code($ec);
    $error_token->error_message($em);
    return base64_encode($error_token->to_token($key));
}

# takes a WebKDC::WebRequest and WebKDC::WebResponse

sub handle_request_token($$) {
    my ($wreq, $wresp) = @_;

    # first parse service-token to get session key

    my $st_str = base64_decode($wreq->service_token());
    my $service_token =
	new WebKDC::WebKDCServiceToken($st_str, get_keyring(), 0);

    print STDERR "$service_token\n" if $DEBUG;

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

    print STDERR "$req_token\n" if $DEBUG;

    # add return_url and post_url if present in request-token
    $wresp->return_url($req_token->return_url());

    # add app_state if present in request-token
    my $as = $req_token->app_state();
    if ($as) {
	$wresp->app_state(base64_encode($as));
    }

    my $rtt = $req_token->requested_token_type();
    #FIXME: ACL CHECK: service-token subject allowed to request
    #       the requested token?

    if ($rtt eq 'id') {
	handle_web_id_request($wreq, $wresp, $service_token, $req_token, $key);
    } else {
	my $ec = WA_PEC_INVALID_REQUEST;
	my $em = "unsupported token type($rtt) in request";
	$wresp->response_token(create_error_token($ec, $em, $key));
    }
}

#
# input:
#    $request_cred hash
# output:
#    base64 service-token
#    base64 session-key
#    ascii expiration time of service token
#
sub create_service_token_from_req($) {
    my ($rc) = @_;

    # only create service tokens from krb5 creds
    if ($rc->{'type'} ne 'krb5') {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
              "can only create service-tokens with <requesterCredential> of ".
              "type krb5");
    }

    #FIXME: ACL CHECK: subject allowed to get a service token?

    my $session_key = base64_encode(WebAuth::random_key(WA_AES_128));
    my $creation_time = time;
    my $expiration_time = $creation_time+$C_SERVICE_TOKEN_LIFETIME;

    my $service_token = new WebKDC::WebKDCServiceToken;

    $service_token->session_key($session_key);
    $service_token->subject($rc->{'subject'});
    $service_token->creation_time($creation_time);
    $service_token->expiration_time($expiration_time);

    return (base64_encode($service_token->to_token(get_keyring())), 
	    $session_key, $expiration_time);
}

sub create_id_token_from_reqsub($$$) {
    my ($e, $rc, $sc) = @_;

    # only create id tokens from 'service' creds
    if ($rc->{'type'} ne 'service') {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
              "can only create id-tokens with <requesterCredential> of ".
              "type service");
    }

    # make sure have a subject credential with type='proxy'
    if ($sc->{'type'} ne 'proxy') {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
              "can only create id-tokens with <subjectCredential> of ".
              "type proxy");
    }

    #FIXME: ACL CHECK: requester allowed to get an id token using
    #       subject cred

    my $st = $rc->{'service_token'};
    my $pt = $sc->{'proxy_token'};

    my $it = new WebKDC::IdToken;
    $it->creation_time(time());
    $it->expiration_time($pt->expiration_time());

    my $ae = $e->find_child('authenticator');
    if (!defined($ae)) {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
			"missing <authenticator> in <token>");
    }
    my $at = $ae->attr('type');

    if ($at eq 'webkdc') {
	$it->subject_auth('webkdc');
	$it->subject($pt->subject());
    } elsif ($at eq 'krb5') {
	if ($pt->proxy_type() ne 'krb5') {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
		"<subjectCredential> proxy-token type not krb5: ".
					      $pt->proxy_type());
	}
	my $c = krb5_new();
	krb5_init_via_tgt($c, $pt->proxy_data());
	# now get subject authenticator
	my $server_principal = $st->subject();
	$server_principal =~ s/^krb5://;
	my $sad = krb5_mk_req($c, $server_principal);
	$it->subject_auth('krb5');
	$it->subject_auth_data($sad);
    } else {
	die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
					  "<authenticator> unknown type: $at");
    }

    return base64_encode($it->to_token($st->session_key()));
}


sub create_proxy_token_from_reqsub($$$) {
    my ($e, $rc, $sc) = @_;

    # only create proxy tokens from 'service' creds
    if ($rc->{'type'} ne 'service') {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
              "can only create proxy-tokens with <requesterCredential> of ".
              "type service");
    }

    # make sure have a subject credential with type='proxy'
    if ($sc->{'type'} ne 'proxy') {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
              "can only create id-tokens with <subjectCredential> of ".
              "type proxy");
    }

    #FIXME: ACL CHECK: requester allowed to get a proxy token using
    #       subject cred

    my $st = $rc->{'service_token'};
    my $pt = $sc->{'proxy_token'};

    my $pte = $e->find_child('proxyType');
    if (!defined($pte)) {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
			"missing <proxyType> in <token>");
    }
    my $req_type = $pte->content_trimmed();
    if ($req_type ne $pt->proxy_type()) {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
	       "can't create proxy-token of type($req_type) from an existing ".
	       "proxy-token of type(".$pt->proxy_type().")");
    }

    # create the webkdc-proxy-token first, using existing proxy-token
    my $new_wpt = new WebKDC::WebKDCProxyToken;
    $new_wpt->proxy_subject($st->subject());
    $new_wpt->proxy_type($pt->proxy_type());
    $new_wpt->proxy_data($pt->proxy_data());
    $new_wpt->subject($pt->subject());
    $new_wpt->creation_time(time());
    $new_wpt->expiration_time($pt->expiration_time());

    # create new proxy-token, with webkdc-proxy-token inside it
    # use new webkdc-proxy-token info to populate
    my $new_pt = new WebKDC::ProxyToken;
    $new_pt->proxy_type($new_wpt->proxy_type());
    $new_pt->webkdc_token($new_wpt->to_token(get_keyring()));
    $new_pt->subject($new_wpt->subject());
    $new_pt->creation_time(time());
    $new_pt->expiration_time($new_wpt->expiration_time());
    return base64_encode($new_pt->to_token($st->session_key()));
}

sub create_cred_token_from_reqsub($$$) {
    my ($e, $rc, $sc) = @_;

    # only create cred tokens from 'service' creds
    if ($rc->{'type'} ne 'service') {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
              "can only create cred-tokens with <requesterCredential> of ".
              "type service");
    }

    # make sure have a subject credential with type='proxy'
    if ($sc->{'type'} ne 'proxy') {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
              "can only create cred-tokens with <subjectCredential> of ".
              "type proxy");
    }

    #FIXME: ACL CHECK: requester allowed to get a cred token using
    #       subject cred

    my $st = $rc->{'service_token'};
    my $pt = $sc->{'proxy_token'};

    my $cte = $e->find_child('credentialType');
    if (!defined($cte)) {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
			"missing <credentialType> in <token>");
    }
    my $req_type = $cte->content_trimmed();

    if ($req_type ne $pt->proxy_type()) {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
	       "can't create cred-token of type($req_type) from an existing ".
	       "proxy-token of type(".$pt->proxy_type().")");
    }

    my $spe = $e->find_child('serverPrincipal');
    if (!defined($spe)) {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
			"missing <serverPrincipal> in <token>");
    }
    my $req_sp = $spe->content_trimmed();


    my $c = krb5_new();
    krb5_init_via_tgt($c, $pt->proxy_data());

    # now get cred data

    my ($cred_data, $cred_expire) = krb5_export_ticket($c, $req_sp);
    my $ct = new WebKDC::CredToken;
    $ct->cred_type($pt->proxy_type());
    $ct->cred_data($cred_data);
    $ct->subject($pt->subject());
    $ct->creation_time(time());
    $ct->expiration_time($cred_expire);
    return base64_encode($ct->to_token($st->session_key()));
}

#
# parses <requesterCredential> and returns a hash:
#
# { 'type' => 'krb5|service',
#   'subject' => 'subject-from-krb5-mk-req-or-service-token',
#   # if type is service
#   'service_token' => $service_token_object,
#   'request_token' => $request_token_object
#  };

sub parse_requesterCredential($) {
    my $e = shift;
    my $req_cred = {};

    my $at = $e->attr('type');
    if ($at eq 'service') {
	$req_cred->{'type'} = $at;
	my ($service_token, $request_token);

	foreach my $child (@{$e->children}) {
	    my $name = $child-->name();
	    if ($name eq 'serviceToken') {
		my $st_str = $child->content_trimmed;
		$service_token = 
		    new WebKDC::WebKDCServiceToken(base64_decode($st_str),
						   get_keyring(), 0);
	    } elsif ($name eq 'requestToken') {
		my $rt_str = $child->content_trimmed;
		$request_token =
		    new WebKDC::WebKDCRequestToken(base64_decode($rt_str),
						   get_keyring(), 0);
	    } else {
		die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
			"invalid element in <requesterCredential>: $name");
	    }
	}

	if (!defined($service_token) || !defined($request_token)) {
		die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
                "<requesterCredential> must have " .
		"<serviceToken> and <requestToken>");
	}
	$req_cred->{'service_token'} = $service_token;
	$req_cred->{'request_token'} = $request_token;
	$req_cred->{'subject'} = $service_token->subject;
	return $req_cred;
    } elsif ($at eq 'krb5') {
	$req_cred->{'type'} = $at;
	my $kreq = $e->content_trimmed;
	my $princ = krb5_rd_req(krb5_new(), base64_decode($kreq), 
				$C_WEBKDC_KEYTAB);
	$req_cred->{'subject'} = "krb5:$princ";
	return $req_cred;
    } else {
	die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
			"unknown <requesterCredential> type($at)");
    }
}


# parses <subjectCredential> and returns a hash:
#
# { 'type' => 'proxy'
#   'proxy_token' => $proxy_token_object
#  };
#

sub parse_subjectCredential($) {
    my $e = shift;
    my $sub_cred = {};

    my $at = $e->attr('type');
    if ($at eq 'proxy') {
	$sub_cred->{'type'} = $at;
	my $pt_str = $e->content_trimmed;
	my $proxy_token =
	    new WebKDC::WebKDCProxy(base64_decode($pt_str), get_keyring(), 0);
	$sub_cred->{'proxy_token'} = $proxy_token;
	return $sub_cred;
    } else {
	die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
			"unknown <subjectCredential> type($at)");
    }
}

# take as input the XmlElement representing the GetTokensRequest and
# return the XmlElemement representing the GetTokensResponse, or 
# throws an exception.

sub handle_getTokensRequest($) {
    my $req = shift;

    my $resp = new WebKDC::XmlDoc;

    my ($tokens,$req_cred, $sub_cred, $mid);
    foreach my $child (@{$req->children()}) {
	my $name = $child->name();
	if ($name eq 'requesterCredential') {
	    $req_cred = parse_requesterCredential($child);
	} elsif ($name eq 'subjectCredential') {
	    $sub_cred = parse_subjectCredential($child);
	} elsif ($name eq 'tokens') {
	    $tokens = $child;
	} elsif ($name eq 'messageId') {
	    $mid = $child->content();
	} else {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
		"invalid element in <getTokensRequest>: $name");
	}
    }

    if (!(defined($tokens) && defined($req_cred))) {
	die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
	     "<getTokensRequest> must have <requesterCredential> ".
	       "and <tokens>");
    }
   
    #FIXME: also need to check for sub_cred in certain cases

    if ($req_cred->{'type'} eq 'service') {
	my $cmd = $req_cred->{'request_token'}->command();
	if ($cmd ne $req->name()) {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
		      "command in request-token not ".$req->name().": $cmd");
	}
    }

    $resp->start('getTokensResponse');

    # add messageId in response if in request
    $resp->start('messageId', undef, $mid)->end() if defined($mid);

    $resp->start('tokens');

    # iterate through each <token>
    foreach my $token (@{$tokens->children}) {
	if ($token->name() ne 'token') {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
			      "invalid element in <tokens>: ".$token->name());
	}

	my $id = $token->attr('id');
	my $tt = $token->attr('type');
	my $td;

	$resp->start('token');
	$resp->current->attr('id', $id) unless !defined($id);

	if ($tt eq 'id') {
	    $td = create_id_token_from_reqsub($token, $req_cred, $sub_cred);
	} elsif ($tt eq 'proxy') {
	    $td = create_proxy_token_from_reqsub($token, $req_cred, $sub_cred);
	} elsif ($tt eq 'service') {
	    my ($key, $et);
	    ($td, $key, $et) = 
		create_service_token_from_req($req_cred);
	    $resp->start('sessionKey', undef, $key)->end();
	    $resp->start('expires', undef, $et)->end();	    
	} elsif ($tt eq 'cred') {
	    $td = create_cred_token_from_reqsub($token, $req_cred, $sub_cred);
	} else {
	    die new WebKDC::ProtocolException(WA_PEC_INVALID_REQUEST,
			"unknown type in <token>: $tt");
	}
	$resp->start('tokenData', undef, $td)->end();
	$resp->end('token');

    }

    $resp->end('tokens');
    $resp->end('getTokensResponse');
    return $resp->root();

}

#
# takes the xml document as a string and returns the response, also
# as a string
#

sub handle_xml_request($) {
    my $xml = shift;

    my ($root, $resp);

    eval {
	$root = new WebKDC::XmlElement($xml);
    };
    if ($@) {
	$resp = create_errorResponse(WA_PEC_INVALID_REQUEST,
				     "Unable to parse request: $@");
	return $resp->to_string(1);
    }

    eval {
	if ($root->name() eq 'getTokensRequest') {
	    $resp = handle_getTokensRequest($root);
	} else {
	    $resp = create_errorResponse(WA_PEC_INVALID_REQUEST,
					 "Unknown command: ".$root->name());
	}
    };

    if (WebKDC::ProtocolException::match($@)) {
	$resp = create_errorResponse($@->status(), $@->message());
    } elsif ($@) {
	#FIXME: in the future, we probably don't want to blindly
	# return the exception as the message, at it might contain
	# sensitive information
	#FIXME: log this
	$resp = create_errorResponse(WA_PEC_SERVER_FAILURE, $@);
    }
    return $resp->to_string(1);
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
    WebKDC::handle_request_token($req, $resp);
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

=handle_request_token(req,resp)

  WebKDC::handle_request_token($req, $resp);

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
  # i.e., enumerate through all cookies that start with webauth_pt
  # and put them into a hash:
  # $cookies = { "webauth_pt_krb5" => $cookie_value }
   
  $req->proxy_cookies($cookies);

  # $req_token_str and $service_token_str would normally get
  # passed in via query/post parameters

  $req->request_token($req_token_str);
  $req->service_token($service_token_str);

  eval {
    WebKDC::handle_request_token($req, $resp);
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
