package WebKDC::Token;

use strict;
use warnings;

use WebAuth;
use UNIVERSAL qw(isa);

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


our %ta_desc = 
    (
     &WebAuth::WA_TK_APP_NAME => 'app-name',
     &WebAuth::WA_TK_CRED_DATA => 'cred-data',
     &WebAuth::WA_TK_CRED_TYPE => 'cred-type',
     &WebAuth::WA_TK_CREATION_TIME => 'creation-time',
     &WebAuth::WA_TK_ERROR_CODE => 'error-code',
     &WebAuth::WA_TK_ERROR_MESSAGE => 'error-message',
     &WebAuth::WA_TK_EXPIRATION_TIME => 'expiration-time',
     &WebAuth::WA_TK_INACTIVITY_TIMEOUT => 'inactivity-timeout',
     &WebAuth::WA_TK_SESSION_KEY => 'session-key',
     &WebAuth::WA_TK_LASTUSED_TIME => 'lastused-time',
     &WebAuth::WA_TK_PROXY_TYPE => 'proxy-type',
     &WebAuth::WA_TK_PROXY_DATA => 'proxy-data',
     &WebAuth::WA_TK_PROXY_OWNER => 'proxy-owner',
     &WebAuth::WA_TK_POST_URL => 'post-url',
     &WebAuth::WA_TK_REQUEST_REASON => 'request-reason',
     &WebAuth::WA_TK_REQ_TOKEN => 'requested-token',
     &WebAuth::WA_TK_REQ_TOKEN_EXPIRATION => 'req-token-exp',
     &WebAuth::WA_TK_REQ_TOKEN_TYPE => 'req-token-type',
     &WebAuth::WA_TK_RETURN_URL => 'return-url',
     &WebAuth::WA_TK_SUBJECT => 'subject',
     &WebAuth::WA_TK_SUBJECT_AUTH => 'subject-auth',
     &WebAuth::WA_TK_SUBJECT_AUTH_DATA => 'subject-auth-data',
     &WebAuth::WA_TK_TOKEN_TYPE => 'token-type',
     );	       

sub get_ta_desc($) {
    my $ta = shift;
    return $ta_desc{$ta} || $ta;
}

sub to_string {
    my ($self) = @_;
    my $attrs = $self->{'attrs'};
    my ($key, $tt, $val, $out);

    $tt = $$attrs{WebAuth::WA_TK_TOKEN_TYPE};
    my $hf="-------------------- $tt token --------------------\n";
    $out = $hf;
    my $fmt = "%20s: %s\n";
    while (($key,$val) = each %$attrs) {
	if ($key eq WebAuth::WA_TK_CREATION_TIME ||
	    $key eq WebAuth::WA_TK_LASTUSED_TIME ||
	    $key eq WebAuth::WA_TK_REQ_TOKEN_EXPIRATION ||
	    $key eq WebAuth::WA_TK_EXPIRATION_TIME) {
	    $val = localtime(unpack("N", $val));
	} elsif ($key eq WebAuth::WA_TK_SESSION_KEY ||
		 $key eq WebAuth::WA_TK_CRED_DATA ||
		 $key eq WebAuth::WA_TK_PROXY_DATA ||
		 $key eq WebAuth::WA_TK_SUBJECT_AUTH_DATA ||
		 $key eq WebAuth::WA_TK_REQ_TOKEN) {
	    $val = WebAuth::hex_encode($val);
	} 
	$out .= sprintf($fmt, get_ta_desc($key), $val);
    }
    $out .= $hf;
    return $out;
}

sub to_token {
    my ($self, $key) = @_;
    my $ct = $self->{'attrs'}{&WebAuth::WA_TK_CREATION_TIME};
    if (defined($ct)) {
	$ct = unpack("N", $ct);
    } else {
	$ct = time();
    }

    return WebAuth::token_create($self->{'attrs'}, $ct, $key);
}

sub to_b64token {
    my ($self, $key) = @_;
    return WebAuth::base64_encode($self->to_token($key));
}

sub from_token {
    my ($self, $token, $key, $ttl) = @_;
    $self->{'attrs'} = WebAuth::token_parse($token, $ttl, $key);
}

sub from_b64token {
    my ($self, $token, $key, $ttl) = @_;
    $self->from_token(WebAuth::base64_decode($token), $key, $ttl);
}

sub set_token_type {
    my ($self, $sa) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_TOKEN_TYPE} = $sa;
    return $self;
}

sub get_token_type {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_TOKEN_TYPE};
}

1;
