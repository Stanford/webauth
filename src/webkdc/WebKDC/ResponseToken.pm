package WebKDC::ResponseToken;

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
    $self->set_token_type('resp');
    return $self;
}

sub is_ok {
    my($self) = @_;

    my $ec = $self->get_error_code();
    return !defined($ec) || ($ec == 0);
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

sub set_error_code {
    my ($self, $val) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_ERROR_CODE} = $val;
    return $self;
}

sub get_error_code {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_ERROR_CODE};
}

sub set_error_message {
    my ($self, $val) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_ERROR_MESSAGE} = $val;
    return $self;
}

sub get_error_message {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_ERROR_MESSAGE};
}

sub set_req_token {
    my ($self, $val) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_REQ_TOKEN} = $val;
    return $self;
}

sub get_req_token {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_REQ_TOKEN};
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

sub set_req_token_exp_time {
    my ($self, $val) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_REQ_TOKEN_EXPIRATION_TIME} = 
	pack("N", $val);
    return $self;
}

sub get_req_token_exp_time {
    my ($self) = @_;
    my $time = $self->{'attrs'}{&WebAuth::WA_TK_REQ_TOKEN_EXPIRATION};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub from_token {
    my ($self, $token, $key, $ttl, $b64) = @_;
    $self->SUPER::from_token($token, $key, $ttl, $b64); 
    if ($self->get_token_type() ne 'resp') {
	die "token_type not 'resp'";
    }
}

1;
