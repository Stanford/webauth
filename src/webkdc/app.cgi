#!/usr/pubsw/bin/perl

use strict;
use warnings;

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
$CONFIG_WEBKDC_LOGIN_URL = "https://lichen.stanford.edu:8443/login";

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

    print STDERR $app_token;

    my $app_token_str = base64_encode($app_token->to_token(get_was_keyring()));

    print STDERR "returning new app_token and cookie!\n";

    my $secure = (defined($ENV{'HTTPS'}) && $ENV{'HTTPS'} eq 'on') ? 1 : 0;

    return ($app_token, $q->cookie(-name => 'webauth_at', 
				   -value => $app_token_str,
	                           -secure => $secure));

}

sub check_for_valid_app_token {
    my $q = shift;

#    my $WR = $q->param('WEBAUTHR');
#    my $WS = $q->param('WEBAUTHS');

    my $URI = $ENV{'REQUEST_URI'};
    my ($WR) = ($URI =~ /;WEBAUTHR=([^;]+);/);
    my ($WS) = ($URI =~ /;WEBAUTHS=([^;]*);/);


    my $at_str = $q->cookie('webauth_at');

    # check for valid cookie first
    if ($at_str) {
	my $app_token;

	eval {
	    $app_token = new WebKDC::AppToken(base64_decode($at_str),
					      get_was_keyring(), 0);
	};
	return ($app_token, undef) if $app_token;
    }

    if ($WR && $WS) {
	my ($app_token, $cookie) = handle_response($q, $WR, $WS);
	return ($app_token, $cookie);
    }
    return (undef, undef);

}

sub redirect_for_webauth_cookie {
    my ($q, $cookie) = @_;


    my $proto = (defined($ENV{'HTTPS'}) &&
		 $ENV{'HTTPS'} eq 'on') ? 'https' : 'http';

    my $return_url = "$proto://".$ENV{'SERVER_NAME'}.":".$ENV{'SERVER_PORT'}.
	$ENV{"REQUEST_URI"};

    
    $return_url =~ s/;WEBAUTHR=.*;$//;
    $return_url =~ s/;WEBAUTHS=.*;$//;

    print STDERR "rfwc: redirect($return_url)\n";
    print STDERR "rfwc: cookie($cookie)\n";

    print "Status: 302 Moved\n";
    print "Location: $return_url\n";
    print "Expires: Thu, 26 Mar 1998 22:00:00 GMT\n";
    print "Pragma: no-cache\n";
    print "Cache-Control: no-cache\n";
    print "Content-Length: 0\n";
    print "Set-Cookie: $cookie\n";
    print "\n";
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

    my $proto = ($ENV{'HTTPS'} eq 'on') ? 'https' : 'http';

    my $return_url = "$proto://".$ENV{'SERVER_NAME'}.":".$ENV{'SERVER_PORT'}.
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
    print "Expires: Thu, 26 Mar 1998 22:00:00 GMT\n";
    print "Pragma: no-cache\n";
    print "Cache-Control: no-cache\n";
    print "Content-Length: 0\n";
    print "\n";
    exit(1);
}

my $q = new CGI;
eval {

    my ($app_token, $cookie);

    eval {
	($app_token, $cookie) = check_for_valid_app_token($q);
    };

    if ($@) {
	print STDERR "exception from cfvat: $@\n";
    }

    if ($cookie) {
	redirect_for_webauth_cookie($q, $cookie);
	exit(1);
    }

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

};

if ($@) {
    my $e = $@;
    print STDERR "app.cgi OOPS: $e\n";
    print $q->header(-type => 'text/plain');
    print "app.cgi OOPS: $e\n";
    exit(1);
}

print "---------------\n";

print "REMOTE_USER = ",$ENV{'REMOTE_USER'},"\n";
print "(note: REMOTE_USER is fully-qualified for now)\n";
print "---------------\n";
exit(0);

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
