package WebKDC::ProxyToken;

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
	$self->init_from_token('proxy', @_);
    } else {
	$self->set_token_type('proxy');
    }
    return $self;
}

sub set_proxy_owner {
    my ($self, $value) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_PROXY_OWNER} = $value;
    return $self;
}

sub get_proxy_owner {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_PROXY_OWNER};
}

sub set_proxy_type {
    my ($self, $value) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_PROXY_TYPE} = $value;
    return $self;
}

sub get_proxy_type {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_PROXY_TYPE};
}

sub set_proxy_data {
    my ($self, $value) = @_;
    $self->{'attrs'}{&WebAuth::WA_TK_PROXY_DATA} = $value;
    return $self;
}

sub get_proxy_data {
    my ($self) = @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_PROXY_DATA};
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

1;
