package WebKDC::Exception;

use strict;
use warnings;

use WebAuth;

use overload '""' => \&to_string;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, @ErrorNames);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter);
    @EXPORT      = qw(WK_ERR_USER_AND_PASS_REQUIRED
		      WK_ERR_LOGIN_FAILED
		      WK_ERR_UNRECOVERABLE_ERROR
		      );
    @EXPORT_OK   = ();
}

our @EXPORT_OK;

sub WK_ERR_USER_AND_PASS_REQUIRED      () {0;}
sub WK_ERR_LOGIN_FAILED                () {1;}
sub WK_ERR_UNRECOVERABLE_ERROR	       () {2;}

our @ErrorNames = qw(USER_AND_PASS_REQUIRED
		     LOGIN_FAILED
		     UNRECOVERABLE_ERROR);

sub new {
    my ($type, $status, $mesg, $wrapped_exception) = @_;
    my $self = {};
    bless $self, $type;
    $self->{'status'} = $status;
    $self->{'mesg'} = $mesg;
    $self->{'wrapped'} = $wrapped_exception;
    return $self;
}

sub status {
    my $self = shift;
    return $self->{'status'};
}

sub message {
    my $self = shift;
    return $self->{'mesg'};
}

sub wrapped_exception {
    my $self = shift;
    return $self->{'wrapped'};
}

sub verbose_message {
    my $self = shift;
    my $s = $self->{'status'};
    my $m = $self->{'mesg'};
    my $w = $self->{'wrapped'};
    my $msg = "WebKDC::Exception ".$ErrorNames[$s].": $m";
    $msg .= ": $w" if (defined($w));
    return $msg;
}

sub to_string {
    my ($self) = @_;
    return $self->verbose_message();
}

sub match {
    my $e = shift;
    return 0 if !isa($e, "WebKDC::Exception");
    return @_ ? $e->status() == shift : 1;
}


1;
