package WebKDC::LoginResponse;

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

sub set_server_principal {
    my ($self, $sp) = @_;
    $self->{'server_principal'} = $sp;
    return $self;
}

sub get_server_principal {
    my ($self) = @_;
    return $self->{'server_principal'};
}

sub set_return_url {
    my ($self, $ru) = @_;
    $self->{'return_url'} = $ru;
    return $self;
}

sub get_return_url {
    my ($self) = @_;
    return $self->{'return_url'};
}

sub set_post_url {
    my ($self, $ru) = @_;
    $self->{'post_url'} = $ru;
    return $self;
}

sub get_post_url {
    my ($self) = @_;
    return $self->{'post_url'};
}

sub add_proxy_cookie {
    my ($self, $type, $value) = @_;
    $self->{'cookies'}{"webauth_pt_$type"} = $value;
    return $self;
}

sub get_proxy_cookie {
    my ($self, $type) = @_;

    return $self->{'cookies'}{"webauth_pt_$type"};
}

sub get_proxy_cookies {
    my ($self) = @_;
    return $self->{'cookies'};
}

sub set_response_token {
    my ($self, $token) = @_;
    $self->{'response_token'} = $token;
    return $self;
}

sub get_response_token {
    my ($self) = @_;
    return $self->{'response_token'};
}

1;

