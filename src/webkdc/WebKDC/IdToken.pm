package WebKDC::IdToken;

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
    if (@_) {
	$self->init_from_token('id', @_);
    } else {
	$self->set_token_type('id');
    }
    return $self;
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

sub set_subject {
    my ($self, $val) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_SUBJECT} = $val;
    return $self;
}

sub get_subject {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_SUBJECT};
}

sub set_subject_auth_data {
    my ($self, $val) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_SUBJECT_AUTH_DATA} = $val;
    return $self;
}

sub get_subject_auth_data {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_SUBJECT_AUTH_DATA};
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

1;
