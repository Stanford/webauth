package WebKDC; 

use strict;
use warnings;

use lib '../bindings/perl/WebAuth/blib/lib';
use lib '../bindings/perl/WebAuth/blib/arch/auto/WebAuth';

use WebAuth qw(:base64 :krb5 :const);
use WebKDC::LoginRequest;
use WebKDC::LoginResponse;
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

    my $service_token = new WebKDC::ServiceToken;

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
    my ($lreq, $lresp, $service_token, $req_token, $key) = @_;

    my $server_principal = $service_token->subject();

    my ($user,$pass) = ($lreq->user(), $lreq->pass());

    my ($et, $sad);

    if (defined($user)) { 	
	# attempt login via user/pass
	my $prd;

	my $c = krb5_new();

	krb5_init_via_password($c, $user, $pass, $C_WEBKDC_KEYTAB);

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
	my $proxy_token = new WebKDC::ProxyToken;
	$proxy_token->proxy_owner("krb5:$webkdc_princ");
	$proxy_token->proxy_type('krb5');
	$proxy_token->proxy_data($prd);
	$proxy_token->subject("krb5:$cp");
	$proxy_token->creation_time(time());
	$proxy_token->expiration_time($et);
	print $proxy_token;
	my $proxy_token_str = 
	    base64_encode($proxy_token->to_token(get_keyring()));
	$lresp->proxy_cookie('krb5', $proxy_token_str);
    } else {
	# init ctxt from tgt
    }

    my $id_token = new WebKDC::IdToken;
    $id_token->subject_auth('krb5');
    $id_token->subject_auth_data($sad);
    $id_token->creation_time(time());
    $id_token->subject_expiration_time($et);


    my $resp_token = new WebKDC::ResponseToken;

    $resp_token->req_token($id_token->to_token($key));
    $resp_token->req_token_type('id');
    $resp_token->creation_time(time());

    $lresp->return_url($req_token->return_url());
    $lresp->post_url($req_token->post_url());
    $lresp->response_token(base64_encode($resp_token->to_token($key)));
    return $lresp;
}


# takes a WebKDC::LoginRequest and returns a WebKDC::LoginResponse

sub process_login_request($) {
    my ($lreq) = @_;

    my $lresp = new WebKDC::LoginResponse;

    # first parse service-token to get session key

    my $service_token = 
	new WebKDC::ServiceToken(base64_decode($lreq->service_token()), 
				 get_keyring(), 0);

    my $server_principal = $service_token->subject();

    if ($server_principal !~ /^krb5:/) {
	die "ERROR: only krb5 principals supported in service tokens";
    }

    # use session key to parse request token
    my $key = WebAuth::key_create(WA_AES_KEY, $service_token->session_key());

    my $req_token = 
	new WebKDC::RequestToken(base64_decode($lreq->request_token()), 
				 $key, $C_TOKEN_TTL);

    # FIXME: would normally poke through request to determine what to do next
    return handle_id_request($lreq, $lresp, $service_token, $req_token, $key);
}


END { }       # module clean-up code here (global destructor)

1;
