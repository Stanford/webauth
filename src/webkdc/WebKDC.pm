package WebKDC; 

use strict;
use warnings;

use lib '../bindings/perl/WebAuth/blib/lib';
use lib '../bindings/perl/WebAuth/blib/arch/auto/WebAuth';

use Carp;
use WebAuth;
use WebKDC::Status;
use WebKDC::LoginRequest;
use WebKDC::LoginResponse;
use WebKDC::IdToken;
use WebKDC::ServiceToken;
use WebKDC::RequestToken;

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

# verify an entered username/password using krb5
# get a subject authenticator for server that requested id token
# get proxy data for proxy-token
#
# takes:
#   $username
#   $password
#   $server_principal
# returns:
#   $s (webauth status)
#   $sad (subject authenticator data)
#   $prd  (proxy data, i.e., exported TGT)
#   $et   (expiration time of proxy data)
#
sub verify_pass_krb5($$$) {
    my ($username, $password, $server_principal) = @_;

    my ($s, $c, $sad, $prd, $et);

    ($s, $c) = WebAuth::krb5_new();

    if ($s != WebAuth::WA_ERR_NONE) {
	croak "",new WebKDC::Status("krb5_new", $s, $c);
    }

    $s = WebAuth::krb5_init_via_password($c, 
					 $username, 
					 $password, 
					 $C_WEBKDC_KEYTAB);

    if ($s != WebAuth::WA_ERR_NONE) {
	croak "", new WebKDC::Status("krb5_init_via_password", $s, $c);
    }
    # now get subject authenticator
    ($s, $sad) = WebAuth::krb5_mk_req($c, $server_principal);

    if ($s != WebAuth::WA_ERR_NONE) {
	croak "",new WebKDC::Status("krb5_mk_req", $s, $c);
    }

    # now get proxy data
    ($s, $prd, $et) = WebAuth::krb5_export_tgt($c);

    if ($s != WebAuth::WA_ERR_NONE) {
	croak "",new WebKDC::Status("krb5_export_tgt", $s, $c);
    }

    return ($sad, $prd, $et);
}

# construct a service token given:
#    $request    from krb5_mk_req (binary)
# returns:
#    $s  (webauth status)
#    $token (binary)
#    $session_key (binary)
#    $expiration_time
#    

sub make_service_token_from_krb5_cred($) {
    my $request = shift;

    my ($s, $clientprinc, $c, $ring);

    ($s, $ring) = WebAuth::keyring_read_file($C_WEBKDC_KEYRING_PATH);
    if ($s != WebAuth::WA_ERR_NONE) {
	croak "",new WebKDC::Status("keyring_read_file", $s);
    }

    # verify request first

    ($s, $c) = WebAuth::krb5_new();

    if ($s != WebAuth::WA_ERR_NONE) {
	croak "",new WebKDC::Status("krb5_new", $s, $c);
    }

    ($s, $clientprinc) = WebAuth::krb5_rd_req($c, $request, $C_WEBKDC_KEYTAB);
    if ($s != WebAuth::WA_ERR_NONE) {
	croak "",new WebKDC::Status("keyring_read_file", $s);
    }

    my $session_key = WebAuth::random_key(WebAuth::WA_AES_128);
    my $creation_time = time;
    my $expiration_time = $creation_time+$C_SERVICE_TOKEN_LIFETIME;

    my $sto = new WebKDC::ServiceToken;

    $sto->set_session_key($session_key);
    $sto->set_subject("krb5:$clientprinc");
    $sto->set_creation_time($creation_time);
    $sto->set_expiration_time($expiration_time);

    my $token;

    $token = $sto->to_b64token($ring);
    return ($token, $session_key, $expiration_time);
}

# takes a WebKDC::LoginRequest and returns a WebKDC::LoginResponse

sub process_login_request($) {
    my ($req) = @_;

    my $resp = new WebKDC::LoginResponse;

    # first parse service-token to get session key

    my ($s, $ring, $key);

    ($s, $ring) = WebAuth::keyring_read_file($C_WEBKDC_KEYRING_PATH);
    if ($s != WebAuth::WA_ERR_NONE) {
	croak "",new WebKDC::Status("keyring_read_file", $s);
    }

    my $sto = new WebKDC::ServiceToken;

    $sto->from_b64token($req->get_service_token(), $ring, $C_TOKEN_TTL);

    my $server_principal = $sto->get_subject();

    if ($server_principal !~ /^krb5:/) {
	die "ERROR: only krb5 principals supported in service tokens";
    }

    # save in response before taking off krb5: prefix
    $resp->set_server_principal($server_principal);

    $server_principal =~ s/^krb5://;

    # use session key to parse request token
    $key = WebAuth::key_create(WebAuth::WA_AES_KEY, $sto->get_session_key());
    if (!defined($key)) {
	die "ERROR: can't create AES key from session key\n";
    }

    my $reqo = new WebKDC::RequestToken;

    $reqo->from_b64token($req->get_request_token(), $key, $C_TOKEN_TTL);

    # FIXME: would normally poke through request to determine what to do next
    $resp->set_return_url($reqo->get_return_url());
    $resp->set_post_url($reqo->get_post_url());

    my ($sad, $prd, $et);

    ($sad, $prd, $et) = verify_pass_krb5($req->get_user(),
					 $req->get_pass(),
					 $server_principal);
    my ($id_token);

    my $ito = new WebKDC::IdToken;
    $ito->set_subject_auth('krb5');
    $ito->set_subject_auth_data($sad);
    $ito->set_creation_time(time());
    $ito->set_expiration_time($et);

    $id_token = $ito->to_token($key);
				      
    my ($response_token);
    my $respo = new WebKDC::ResponseToken;

    $respo->set_req_token($id_token);
    $response_token = $respo->to_b64token($key);
    $resp->set_response_token($response_token);
    return $resp;
}


END { }       # module clean-up code here (global destructor)

1;
