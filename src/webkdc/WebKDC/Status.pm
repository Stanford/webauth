package WebKDC::Status;

use strict;
use warnings;

use WebAuth;

use overload '""' => \&to_string;

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
    my ($type, $detail, $s, $kc) = @_;
    my $self = {};
    bless $self, $type;
    $self->{'status'} = $s;
    $self->{'detail'} = $detail;
    if (defined($kc) && $s == WebAuth::WA_ERR_KRB5) {
	$self->{'krb5_ec'} = WebAuth::krb5_error_message($kc);
	$self->{'krb5_em'} = WebAuth::krb5_error_code($kc);
    }
    return $self;
}

sub check {
    my ($s, $kc) = @_;
    if ($s != WebAuth::WA_ERR_NONE) {
	return new WebKDC::Status($s, $kc);
    } else {
	return undef;
    }
}

sub ok {
    my ($self) = @_;
    return $self->{'status'} == WebAuth::WA_ERR_NONE;
}

sub get_status {
    my ($self) = @_;
    return $self->{'status'};
}

sub get_krb5_error_code {
    my ($self) = @_;
    return $self->{'krb5_ec'};
}

sub get_krb5_error_message {
    my ($self) = @_;
    return $self->{'krb5_em'};
}

sub get_message {
    my ($self) = @_;
    my $s = $self->{'status'};
    my $msg = WebAuth::error_message($s);
    my $detail = $self->{'detail'};
    if (defined($detail)) {
	$msg = "$detail: $msg";
    }
    if ($s == WebAuth::WA_ERR_KRB5) {
	my $kec = $self->{'krb5_ec'};
	my $kem = $self->{'krb5_em'};
	$msg .= ": $kem ($kec)";
    }
    return $msg;
}

sub to_string {
    my ($self) = @_;
    return $self->get_message();
}

1;
