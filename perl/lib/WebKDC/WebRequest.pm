# An object encapsulating a request to a WebKDC.
#
# Written by Roland Schemers
# Copyright 2002, 2003, 2005, 2009
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebKDC::WebRequest;

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

sub user {
    my $self = shift;
    $self->{'user'} = shift if @_;
    return $self->{'user'};
}

sub pass {
    my $self = shift;
    $self->{'pass'} = shift if @_;
    return $self->{'pass'};
}

sub otp {
    my $self = shift;
    $self->{'otp'} = shift if @_;
    return $self->{'otp'};
}

sub proxy_cookie {
    my $self = shift;
    my $type = shift;
    if (@_ == 2) {
        my ($cookie, $session_factor) = @_;
        $self->{'cookies'}{$type}{'cookie'} = $cookie;
        $self->{'cookies'}{$type}{'session_factor'} = $session_factor;
    }
    return $self->{'cookies'}{$type};
}

sub proxy_cookies {
    my $self = shift;
    $self->{'cookies'} = shift if @_;
    my (%cookies);
    foreach my $type (keys %{$self->{'cookies'}}) {
        $cookies{$type} = $self->{'cookies'}{$type}{'cookie'};
    }
    return \%cookies;
}

sub proxy_cookies_rich {
    my $self = shift;
    $self->{'cookies'} = shift if @_;
    return $self->{'cookies'};
}

sub request_token {
    my $self = shift;
    $self->{'request_token'} = shift if @_;
    return $self->{'request_token'};
}

sub service_token {
    my $self = shift;
    $self->{'service_token'} = shift if @_;
    return $self->{'service_token'};
}


sub local_ip_addr {
    my $self = shift;
    $self->{'local_ip_addr'} = shift if @_;
    return $self->{'local_ip_addr'};
}

sub local_ip_port {
    my $self = shift;
    $self->{'local_ip_port'} = shift if @_;
    return $self->{'local_ip_port'};
}

sub remote_ip_addr {
    my $self = shift;
    $self->{'remote_ip_addr'} = shift if @_;
    return $self->{'remote_ip_addr'};
}

sub remote_ip_port {
    my $self = shift;
    $self->{'remote_ip_port'} = shift if @_;
    return $self->{'remote_ip_port'};
}

sub remote_user {
    my $self = shift;
    $self->{'remote_user'} = shift if @_;
    return $self->{'remote_user'};
}

1;
