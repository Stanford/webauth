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

# initialize package globals, first exported ones
#$Var1   = '';

# then the others (which are still accessible as $Some::Module::stuff)
#@more   = ();

# all file-scoped lexicals must be created before
# the functions below that use them.

# file-private lexicals go here
#my $priv_var    = '';

# functions

sub check_error($$;$) {
    my ($s, $m, $c) = @_;
    if ($s == WebAuth::WA_ERR_NONE) {
	return 0;
    } elsif ($s != WebAuth::WA_ERR_KRB5 || $c == undef) {
	print "ERROR: $m webauth error($s)\n";
	return 1;
    } else {
	my $kc = WebAuth::krb5_error_code($c);
	my $km = WebAuth::krb5_error_message($c);
	print "ERROR: $m krb5 error code($kc) message($km)\n";
	return 1;
    }
}

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

    if (check_error($s, "krb5_new", $c)) {
	return ($s, undef, undef, undef);
    }

    $s = WebAuth::krb5_init_via_password($c, 
					 $username, 
					 $password, 
					 $C_WEBKDC_KEYTAB);

    if (check_error($s, "krb5_init_via_password", $c)) {
	return ($s, undef, undef, undef);
    }
    
    # now get subject authenticator
    ($s, $sad) = WebAuth::krb5_mk_req($c, $server_principal);

    if (check_error($s, "krb5_init_via_password", $c)) {
	return ($s, undef, undef, undef);
    }

    # now get proxy data
    ($s, $prd, $et) = WebAuth::krb5_export_tgt($c);
    if (check_error($s, "krb5_init_via_password", $c)) {
	return ($s, undef, undef, undef);
    }

    return ($s, $sad, $prd, $et);
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
    if (check_error($s, "keyring_read_file ", undef)) {
	return ($s, undef, undef, undef);
    }

    # verify request first

    ($s, $c) = WebAuth::krb5_new();

    if (check_error($s, "krb5_new", $c)) {
	return ($s, undef, undef, undef);
    }

    ($s, $clientprinc) = WebAuth::krb5_rd_req($c, $request, $C_WEBKDC_KEYTAB);

    if (check_error($s, "krb5_rd_req", $c)) {
	return ($s, undef, undef, undef);
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

    ($s, $token) = $sto->to_b64token($ring);

    if ($s != WebAuth::WA_ERR_NONE) {
	return ($s, undef, undef, undef);
    } else  {
	return ($s, $token, $session_key, $expiration_time);
    }
}

# takes a WebKDC::LoginRequest and returns a WebKDC::LoginResponse

sub process_login_request($) {
    my ($req) = @_;

    my $resp = new WebKDC::LoginResponse;

    # first parse service-token to get session key

    my ($s, $ring, $key);

    ($s, $ring) = WebAuth::keyring_read_file($C_WEBKDC_KEYRING_PATH);
    if (check_error($s, "keyring_read_file", undef)) {
	return $resp->set_status($s);
    }

    my $sto = new WebKDC::ServiceToken;

    $s = $sto->from_b64token($req->get_service_token(), $ring, $C_TOKEN_TTL);

    if (check_error($s, "sto from_b64token", undef)) {
	return $resp->set_status($s);
    }

    my $server_principal = $sto->get_subject();

    if ($server_principal !~ /^krb5:/) {
	#FIXME: need better error code
	return $resp->set_status(WebAuth::WA_ERR_CORRUPT);
    }

    # save in response before taking off krb5: prefix
    $resp->set_server_principal($server_principal);

    $server_principal =~ s/^krb5://;

    # use session key to parse request token
    $key = WebAuth::key_create(WebAuth::WA_AES_KEY, $sto->get_session_key());
    if (!defined($key)) {
	print "ERROR: can't create AES key from session key\n";
	return $resp->set_status(WebAuth::WA_ERR_BAD_KEY);
    }

    my $reqo = new WebKDC::RequestToken;

    $s = $reqo->from_b64token($req->get_request_token(), $key, $C_TOKEN_TTL);
    if (check_error($s, "rto from_b64token", undef)) {
	return $resp->set_status($s);
    }

    # FIXME: would normally poke through request to determine what to do next

    $resp->set_return_url($reqo->get_return_url());
    $resp->set_post_url($reqo->get_post_url());

    my ($sad, $prd, $et);

    ($s, $sad, $prd, $et) = verify_pass_krb5($req->get_user(),
					     $req->get_pass(),
					     $server_principal);
    if (check_error($s, "verify_pass_krb5", undef)) {
	return $resp->set_status($s);
    }

    my ($id_token);

    my $ito = new WebKDC::IdToken;
    $ito->set_subject_auth('krb5');
    $ito->set_subject_auth_data($sad);
    $ito->set_creation_time(time());
    $ito->set_expiration_time($et);

    ($s, $id_token) = $ito->to_token($key);
				      
    if (check_error($s, "create_id_token", undef)) {
	return $resp->set_status($s);
    }

    my ($response_token);
    my $respo = new WebKDC::ResponseToken;

    $respo->set_req_token($id_token);
    ($s, $response_token) = $respo->to_b64token($key);
    if (check_error($s, "create_id_token", undef)) {
	return $resp->set_status($s);
    }
    $resp->set_response_token($response_token);
    $resp->set_status(WebAuth::WA_ERR_NONE);
    return $resp;
}


END { }       # module clean-up code here (global destructor)

1;
