package WebKDC::LoginRequest;

use strict;
use warnings;

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

sub new {
    my $type = shift;
    my $self = {};
    bless $self, $type;
    return $self;
}

sub set_user {
    my ($self, $user) = @_;
    $self->{'user'} = $user;
    return $self;
}

sub get_user {
    my ($self) = @_;
    return $self->{'user'};
}

sub set_pass {
    my ($self, $pass) = @_;
    $self->{'pass'} = $pass;
    return $self;
}

sub get_pass {
    my ($self) = @_;
    return $self->{'pass'};
}

sub add_proxy_cookie {
    my ($self, $name, $value) = @_;
    $self->{'cookies'}{$name} = $value;
    return $self;
}

sub get_proxy_cookie {
    my ($self, $name) = @_;
    return $self->{'cookies'}{$name};
}

sub get_proxy_cookies {
    my ($self) = @_;
    return $self->{'cookies'};
}

sub set_request_token {
    my ($self, $token) = @_;
    $self->{'request_token'} = $token;
    return $self;
}

sub get_request_token {
    my ($self) = @_;
    return $self->{'request_token'};
}

sub set_service_token {
    my ($self, $token) = @_;
    $self->{'service_token'} = $token;
    return $self;
}

sub get_service_token {
    my ($self) = @_;
    return $self->{'service_token'};
}

1;
