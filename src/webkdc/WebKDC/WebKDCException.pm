package WebKDC::WebKDCException;

use strict;
use warnings;

use WebAuth;

use UNIVERSAL qw(isa);

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

sub WK_ERR_USER_AND_PASS_REQUIRED      () {1;}
sub WK_ERR_LOGIN_FAILED                () {2;}
sub WK_ERR_UNRECOVERABLE_ERROR	       () {3;}

our @ErrorNames = qw(UNUSED USER_AND_PASS_REQUIRED
		     LOGIN_FAILED
		     UNRECOVERABLE_ERROR);

sub new {
    my ($type, $status, $mesg, $pec) = @_;
    my $self = {};
    bless $self, $type;
    $self->{'status'} = $status;
    $self->{'mesg'} = $mesg;
    $self->{'pec'} = $pec;
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

sub error_code {
    my $self = shift;
    return $self->{'pec'};
}

sub verbose_message {
    my $self = shift;
    my $s = $self->{'status'};
    my $m = $self->{'mesg'};
    my $pec = $self->{'pec'};
    my $msg = "WebKDC::WebKDCException ".$ErrorNames[$s].": $m";
    $msg .= ": WebKDC errorCode: $pec" if (defined($pec));
    return $msg;
}

sub to_string {
    my ($self) = @_;
    return $self->verbose_message();
}

sub match {
    my $e = shift;
    return 0 if !isa($e, "WebKDC::WebKDCException");
    return @_ ? $e->status() == shift : 1;
}


1;

__END__

=head1 NAME

WebKDC::WebKDCException - exceptions for WebKDC

=head1 SYNOPSIS

  use WebKDC;
  use WebKDC::WebKDCException;

  eval {  
    ...
    WebKDC::request_token_request($req, $resp);
    ...
  };
  if (WebKDC::WebKDCException::match($@)) {
    my $e = $@;
    # you can call the following methods on a WebKDCException object:
    # $e->status()
    # $e->message()
    # $e->error_code()
    # $e->verbose_message()
  }

=head1 DESCRIPTION

The various WebKDC functions can all throw WebKDCException if something
wrong happens.

=head1 EXPORT

The following constants are exported:

  WK_ERR_USER_AND_PASS_REQUIRED
  WK_ERR_LOGIN_FAILED
  WK_ERR_UNRECOVERABLE_ERROR

=over 4

=item WK_ERR_USER_AND_PASS_REQUIRED

 This status code indicates that a function was called
 that required a username and password. The user should
 be prompted for their username and the function should be
 called again.

=item WK_ERR_LOGIN_FAILED

 This status code indicates that a function was called
 that attempted to validate the username and password and
 could not, due to an invalid user or password. The
 user should be re-prompted for their username/password
 and the function should be called again.

=item WK_ERR_UNRECOVERABLE_ERROR

 This status code indicates that a function was called
 and an error occured that can not be recovered from. If
 you are in the process of attempting to log a user in,
 you have no choice but to display an error message to
 the user and not prompt again.

=back

=head1 METHODS and FUNCTIONS

=over 4

=item match($exception[, $status])

  This class function (not a method) returns true if the given
  $exception is a WebKDC::WebKDCException. If $status is specified, then
  $exception->status() will also be compared to $status.

=item new(status, message, wrapped_exception)

  This method is used to created new WebKDC::WebKDCException objects.

=item status()

  This method returns the WebKDC::WebKDCException status code for the exception,
  which will be one of the WK_ERR_* codes.

=item message()

  This method returns the error message that was
  used in the constructor.

=item error_code()

  This method returns the WebKDC errorCode (if there was one).

=item verbose_message()

  This method returns a verbose error message, which consists
  of the status code, message, and any error code.

  The verbose_message method is also called if the exception is
  used as a string.

=back

=head1 AUTHOR

Roland Schemers (schemers@stanford.edu)

=head1 SEE ALSO

L<WebKDC>.

=cut
