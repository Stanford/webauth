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

sub proxy_cookie {
    my $self = shift;
    my $type = shift;
    $self->{'cookies'}{"webauth_wpt_$type"} = shift if @_;
    return $self->{'cookies'}{"webauth_wpt_$type"};
}

sub proxy_cookies {
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

1;
