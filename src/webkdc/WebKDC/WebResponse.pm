package WebKDC::WebResponse;

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

sub return_url {
    my $self = shift;
    $self->{'return_url'} = shift if @_;
    return $self->{'return_url'};
}

sub proxy_cookie {
    my $self = shift;
    my $type = shift;
    $self->{'cookies'}{$type} = shift if @_;
    return $self->{'cookies'}{$type};
}

sub proxy_cookies {
    my $self = shift;
    return $self->{'cookies'};
}

sub response_token {
    my $self = shift;
    $self->{'response_token'} = shift if @_;
    return $self->{'response_token'};
}

sub login_canceled_token {
    my $self = shift;
    $self->{'lc_token'} = shift if @_;
    return $self->{'lc_token'};
}

sub requester_subject {
    my $self = shift;
    $self->{'requester_subject'} = shift if @_;
    return $self->{'requester_subject'};
}

sub app_state {
    my $self = shift;
    $self->{'app_state'} = shift if @_;
    return $self->{'app_state'};
}

1;
