package WebKDC; 

use strict;
use warnings;

use lib '../bindings/perl/WebAuth/blib/lib';
use lib '../bindings/perl/WebAuth/blib/arch/auto/WebAuth';

use WebAuth;
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

    my $c = WebAuth::krb5_new();

    WebAuth::krb5_init_via_password($c, $username, $password, 
				    $C_WEBKDC_KEYTAB);

    # now get subject authenticator
    my $sad = WebAuth::krb5_mk_req($c, $server_principal);

    # now get proxy data
    my ($prd, $et) = WebAuth::krb5_export_tgt($c);
    return ($sad, $prd, $et);
}

# construct a service token given:
#    $request    from krb5_mk_req (binary)
# returns:
#    $token (b64
#    $session_key (binary)
#    $expiration_time
#    

sub make_service_token_from_krb5_cred($) {
    my $request = shift;

    my $ring = WebAuth::keyring_read_file($C_WEBKDC_KEYRING_PATH);

    # verify request first
    my $c = WebAuth::krb5_new();

    my $clientprinc = WebAuth::krb5_rd_req($c, $request, $C_WEBKDC_KEYTAB);

    my $session_key = WebAuth::random_key(WebAuth::WA_AES_128);
    my $creation_time = time;
    my $expiration_time = $creation_time+$C_SERVICE_TOKEN_LIFETIME;

    my $service_token = new WebKDC::ServiceToken;

    $service_token->set_session_key($session_key);
    $service_token->set_subject("krb5:$clientprinc");
    $service_token->set_creation_time($creation_time);
    $service_token->set_expiration_time($expiration_time);

    return ($service_token->to_b64token($ring), 
	    $session_key, $expiration_time);
}

# takes a WebKDC::LoginRequest and returns a WebKDC::LoginResponse

sub process_login_request($) {
    my ($req) = @_;

    my $resp = new WebKDC::LoginResponse;

    # first parse service-token to get session key

    my $ring = WebAuth::keyring_read_file($C_WEBKDC_KEYRING_PATH);

    my $service_token = new WebKDC::ServiceToken($req->get_service_token(), 
				       $ring, $C_TOKEN_TTL, 1);

    my $server_principal = $service_token->get_subject();

    if ($server_principal !~ /^krb5:/) {
	die "ERROR: only krb5 principals supported in service tokens";
    }

    # save in response before taking off krb5: prefix
    $resp->set_server_principal($server_principal);

    $server_principal =~ s/^krb5://;

    # use session key to parse request token
    my $key = WebAuth::key_create(WebAuth::WA_AES_KEY, 
				  $service_token->get_session_key());

    my $req_token = new WebKDC::RequestToken($req->get_request_token(), 
					     $key, $C_TOKEN_TTL, 1);

    # FIXME: would normally poke through request to determine what to do next
    $resp->set_return_url($req_token->get_return_url());
    $resp->set_post_url($req_token->get_post_url());

    my ($sad, $prd, $et) = verify_pass_krb5($req->get_user(),
					    $req->get_pass(),
					    $server_principal);
    my ($id_token);

    my $ito = new WebKDC::IdToken;
    $ito->set_subject_auth('krb5');
    $ito->set_subject_auth_data($sad);
    $ito->set_creation_time(time());
    $ito->set_expiration_time($et);

    $id_token = $ito->to_token($key);
				      
    my $resp_token = new WebKDC::ResponseToken;

    $resp_token->set_req_token($id_token);
    $resp_token->set_creation_time(time());

    $resp->set_response_token($resp_token->to_b64token($key));
    return $resp;
}


END { }       # module clean-up code here (global destructor)

1;
