package WebKDC::RequestToken;

use strict;
use warnings;

use WebAuth;
use WebKDC::Token;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter WebKDC::Token);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;

sub new {
    my $type = shift;
    my $self = { "attrs" => {}};
    bless $self, $type;
    $self->set_token_type('req');
    return $self;
}

sub set_creation_time {
    my ($self, $val) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_CREATION_TIME} = pack("N", $val);
    return $self;
}

sub get_creation_time {
    my ($self) = @_;
    my $time = $self->{'attrs'}{&WebAuth::WA_TK_CREATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub set_subject_auth {
    my ($self, $sa) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_SUBJECT_AUTH} = $sa;
    return $self;
}

sub get_subject_auth {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_SUBJECT_AUTH};
}

sub set_request_reason {
    my ($self, $sa) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_REQUEST_REASON} = $sa;
    return $self;
}

sub get_request_reason {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_REQUEST_REASON};
}

sub set_req_token_type {
    my ($self, $val) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_REQ_TOKEN_TYPE} = $val;
    return $self;
}

sub get_req_token_type {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_REQ_TOKEN_TYPE};
}

sub set_proxy_type {
    my ($self, $val) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_PROXY_TYPE} = $val;
    return $self;
}

sub get_proxy_type {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_PROXY_TYPE};
}

sub set_return_url {
    my ($self, $sa) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_RETURN_URL} = $sa;
    return $self;
}

sub get_return_url {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_RETURN_URL};
}

sub set_post_url {
    my ($self, $sa) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_POST_URL} = $sa;
    return $self;
}

sub get_post_url {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_POST_URL};
}

sub from_token {
    my ($self, $token, $key, $ttl, $b64) = @_;
    my $s = $self->SUPER::from_token($token, $key, $ttl, $b64); 
    if (($s == WebAuth::WA_ERR_NONE) && ($self->get_token_type() ne 'req')) {
	die "token_type not 'req'";
    }
    return $s;
}

1;
