package WebKDC::ProtocolException;

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
    @EXPORT      = qw();
    @EXPORT_OK   = ();
}

our @EXPORT_OK;

sub new {
    my ($type, $status, $mesg) = @_;
    my $self = {};
    bless $self, $type;
    $self->{'status'} = $status;
    $self->{'mesg'} = $mesg;
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


sub verbose_message {
    my $self = shift;
    my $s = $self->{'status'};
    my $m = $self->{'mesg'};
    my $msg = "WebKDC::ProtocolException $s: $m";
    return $msg;
}

sub to_string {
    my ($self) = @_;
    return $self->verbose_message();
}

sub match {
    my $e = shift;
    return 0 if !isa($e, "WebKDC::ProtocolException");
    return @_ ? $e->status() == shift : 1;
}


1;

__END__

=head1 NAME

WebKDC::ProtocolException - WebAuth protocol exceptions for WebKDC

=head1 SYNOPSIS

  use WebKDC;
  use WebKDC::ProtocolException;

  eval {  
    ...
    WebKDC::FOO
    ...
  };
  if (WebKDC::Exception::match($@)) {
    my $e = $@;
    # you can call the following methods on an Exception object:
    # $e->status()
    # $e->message()
    # $e->wrapped_exception()
    # $e->verbose_message()
  }

=head1 DESCRIPTION

The various WebKDC functions can all throw WebKDC::ProtocolExceptions if 
something wrong happens. The exceptions correspond to WA_PEC_* errors.

=head1 EXPORT

no constants are exported. You'lll most likely want to import constants
from WebAuth though, so you can use the WA_PEC_* constants:

use WebAuth qw(:const);

=over 4

=item WA_PEC_SERVICE_TOKEN_EXPIRED

 This status code indicates that a service token used with a request
 was expired.

=item WA_PEC_PROXY_TOKEN_EXPIRED

 This status code indicates that a proxy token used with a request
 was expired.

=item WA_PEC_INVALID_REQUEST

 This status code indicates that some part of the request was invalid
 (invalid element, attribute, etc). The error message will contain 
 detailed information about what was wrong.

=item WA_PEC_UNAUTHORIZED

 This status code indicates that the caller was not authorized to
 make the request.

=back


=head1 METHODS and FUNCTIONS

=over 4

=item match($exception[, $status])

  This class function (not a method) returns true if the given
  $exception is a WebAuth::ProtocolException. If $status is specified, then
  $exception->status() will also be compared to $status.

=item new(status, message)

  This method is used to created new WebKDC::ProtcolException objects.

=item status()

  This method returns the WebKDC::ProtocolException status code 
  for the exception,  which will be one of the WA_PEC_* codes.

=item message()

  This method returns the rror message that was
  used in the constructor.

=item verbose_message()

  This method returns a verbose error message, which consists
  of the status code and message.

  The verbose_message method is also called if the exception is
  used as a string.

=back

=head1 AUTHOR

Roland Schemers (schemers@stanford.edu)

=head1 SEE ALSO

L<WebKDC>.

=cut
