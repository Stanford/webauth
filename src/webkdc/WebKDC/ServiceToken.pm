package WebKDC::ServiceToken;

use strict;
use warnings;

use WebAuth;
use WebKDC::Token;

use Carp;

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

sub init {
    my $self = shift;
    $self->token_type('service');
}

sub session_key {
    my $self = shift;
    $self->{'attrs'}{&WebAuth::WA_TK_SESSION_KEY} = shift if @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_SESSION_KEY};    
}

sub subject {
    my $self = shift;
    $self->{'attrs'}{&WebAuth::WA_TK_SUBJECT} = shift if @_;
    return $self->{'attrs'}{&WebAuth::WA_TK_SUBJECT};
}

sub creation_time {
    my $self = shift;
    $self->{'attrs'}{&WebAuth::WA_TK_CREATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WebAuth::WA_TK_CREATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub expiration_time {
    my $self = shift;
    $self->{'attrs'}{&WebAuth::WA_TK_EXPIRATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WebAuth::WA_TK_EXPIRATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub validate_token {
    my $self = shift;

    croak "validate_token failed" unless
	($self->token_type() eq 'service') && 
	defined($self->session_key()) &&
	defined($self->subject()) &&
	defined($self->creation_time()) &&
	defined($self->expiration_time());
}

1;
