#!/usr/pubsw/bin/perl

use strict;
use warnings;

#use lib '../bindings/perl/WebAuth/blib/lib';
#use lib '../bindings/perl/WebAuth/blib/arch/auto/WebAuth';

use WebAuth qw(:base64 :const :krb5 :key);
use WebKDC;

use UNIVERSAL qw(isa);

use CGI qw/:standard/;
use Dumpvalue;
use Carp;


use vars qw($CONFIG_WAS_KEYTAB 
	    $CONFIG_WAS_KEYRING_PATH $CONFIG_WEBKDC_LOGIN_URL);

$CONFIG_WAS_KEYTAB = "shred_webauth.keytab";
$CONFIG_WAS_KEYRING_PATH = "was.keyring";
$CONFIG_WEBKDC_LOGIN_URL = "http://lichen.stanford.edu:8080/login";

our $our_keyring = undef;

sub get_was_keyring {
    if (!defined($our_keyring)) {
	$our_keyring = WebAuth::keyring_read_file($CONFIG_WAS_KEYRING_PATH);
    }
    return $our_keyring;
}

sub dump_stuff {
    my ($var, $val);
    foreach $var (sort(keys(%ENV))) {
	$val = $ENV{$var};
	$val =~ s|\n|\\n|g;
	$val =~ s|"|\\"|g;
	print "${var}=\"${val}\"\n";
    }
    
    print "\n";
    print "\n";
    while(<STDIN>) {
	print "INPUT: $_";
    }
}

sub handle_response($$$) {
    my ($q, $resp_token_str, $as_token_str) = @_;

    $resp_token_str =~ tr/ /+/;
    $as_token_str =~ tr/ /+/;
    
    my $as_token = new WebKDC::AppToken(base64_decode($as_token_str),
					get_was_keyring(), 0);

    my $key = key_create(WA_AES_KEY, $as_token->session_key());

    my $id_token = WebKDC::Token::parse(base64_decode($resp_token_str),
					$key, $WebKDC::C_TOKEN_TTL);

    if (!isa($id_token, 'WebKDC::IdToken')) {
	print STDERR $id_token;
	exit(1);
	#croak "response not an IdToken";

    }
    print STDERR $id_token;

    my $sad = $id_token->subject_auth_data();
    my $id_princ = krb5_rd_req(krb5_new(), $sad, $CONFIG_WAS_KEYTAB);

    print STDERR "id = $id_princ\n";

    my $app_token = new WebKDC::AppToken;

    $app_token->subject("krb5:$id_princ");
    $app_token->creation_time(time());
    $app_token->expiration_time($id_token->expiration_time());

    #print $app_token;

    my $app_token_str = base64_encode($app_token->to_token(get_was_keyring()));

    return ($app_token, $q->cookie(-name => 'webauth_at', 
				   -value => $app_token_str));

}

sub check_for_valid_app_token {
    my $q = shift;

    my $WR = $q->param('WEBAUTHR');
    my $WS = $q->param('WEBAUTHS');

    if ($WR && $WS) {
	my ($app_token, $cookie) = handle_response($q, $WR, $WS);
	return ($app_token, $cookie);
    }

    my $at_str = $q->cookie('webauth_at');
    return undef unless $at_str;

    my $app_token = undef;
    eval {
	print STDERR "parse $at_str\n";

	$app_token = new WebKDC::AppToken(base64_decode($at_str),
					  get_was_keyring(), 0);
    };

    if ($@) {
	print STDERR "apptoken exception: $@\n";
    }
    return ($app_token, undef);
}

sub old_redirect_for_webauth_login {
    my $q = shift;

    my $app_token = new WebKDC::AppToken;

    $app_token->subject("schemers");
    $app_token->creation_time(time());
    $app_token->expiration_time(time()+3600);
    my $app_token_str = base64_encode($app_token->to_token(get_was_keyring()));

    my $cookie = $q->cookie(-name=>'webauth_at',
			-value=> $app_token_str,
			-path=>'/');
    print $q->header(-type => 'text/plain',
		     -cookie => [$cookie],
		     );
    print "cookie set\n";
    exit(1);
}

sub redirect_for_webauth_login {
    my $q = shift;

    # normally we would use a cached service-token or
    # or make one via the xml interface, for now, we call
    # into the WebKDC directly

    my $c = krb5_new();

    krb5_init_via_keytab($c, $CONFIG_WAS_KEYTAB);

    my $princ = krb5_service_principal($c, $WebKDC::C_WEBKDC_K5SERVICE,
				       $WebKDC::C_WEBKDC_HOST);
    my $request = krb5_mk_req($c, $princ);

    my ($service_token_str, $session_key, $st_expiration_time) =
	WebKDC::make_service_token_from_krb5_cred($request);

    my $key = key_create(WA_AES_KEY, $session_key);

    my $as_token = new WebKDC::AppToken;

    $as_token->session_key($session_key);
    $as_token->expiration_time($st_expiration_time);

    print STDERR $as_token;

    my $return_url = "http://".$ENV{'SERVER_NAME'}.":".$ENV{'SERVER_PORT'}.
	$ENV{"REQUEST_URI"};
	
    my $req_token = new WebKDC::RequestToken;
    $req_token->app_state($as_token->to_token(get_was_keyring()));
    $req_token->return_url($return_url);
    $req_token->creation_time(time());
    $req_token->request_reason('na');
    $req_token->requested_token_type('id');
    $req_token->subject_auth('krb5');

    print STDERR "$req_token\n";

    my $req_token_str = base64_encode($req_token->to_token($key));

    my $redirect_url = 
	"$CONFIG_WEBKDC_LOGIN_URL?RT=$req_token_str;ST=$service_token_str";
    print STDERR "redirect url($redirect_url)\n";

    print "Status: 302 Moved\n";
    print "Location: $redirect_url\n";
    print "Expires: Tue, 06 Jul 1999 22:00:00 GMT\n";
    print "Pragma: no-cache\n";
    print "Cache-Control: no-cache\n";
    print "Content-Length: 0\n";
    print "\n";
    exit(1);
}

my $q = new CGI;

my ($app_token, $cookie) = check_for_valid_app_token($q);

if (!$app_token) {
    redirect_for_webauth_login($q);
    exit(1);
}

$ENV{'REMOTE_USER'} = $app_token->subject();

if ($cookie) {
    print $q->header(-type => 'text/plain', -cookie => $cookie);
} else {
    print $q->header(-type => 'text/plain');
}


print "---------------\n";
dump_stuff;
print "---------------\n";
my $params = $q->Vars;

my $dumper = new Dumpvalue;
$dumper->dumpValue($params);

print "---------------\n";

print $q->Dump;

print "---------------\n";

print $q->cookie('webauth_at'), "\n";

print "---------------\n";
