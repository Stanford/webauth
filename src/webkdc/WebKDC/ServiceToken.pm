package WebKDC::ServiceToken;

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
    $self->set_token_type('service');
    return $self;
}

sub set_session_key {
    my ($self, $sa) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_SESSION_KEY} = $sa;
    return $self;
}

sub get_session_key {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_SESSION_KEY};
}

sub set_subject {
    my ($self, $val) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_SUBJECT} = $val;
    return $self;
}

sub get_subject {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_SUBJECT};
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

sub set_expiration_time {
    my ($self, $val) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_EXPIRATION_TIME} = pack("N", $val);
    return $self;
}

sub get_expiration_time {
    my ($self) = @_;
    my $time = $self->{'attrs'}{&WebAuth::WA_TK_EXPIRATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub from_token {
    my ($self, $token, $key, $ttl, $b64) = @_;
    $self->SUPER::from_token($token, $key, $ttl, $b64); 
    if ($self->get_token_type() ne 'service') {
	die "from_token: token type not 'service'";
    }
}

1;
