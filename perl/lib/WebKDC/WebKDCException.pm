# Exception class for WebKDC call failures.
#
# Written by Roland Schemers
# Copyright 2002, 2003, 2005, 2006, 2008, 2009, 2011
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebKDC::WebKDCException;

use strict;
use warnings;

use overload '""' => \&to_string;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, @ErrorNames);

    # set the version for version checking
    $VERSION     = 1.02;
    @ISA         = qw(Exporter);
    @EXPORT      = qw(WK_SUCCESS
		      WK_ERR_USER_AND_PASS_REQUIRED
		      WK_ERR_LOGIN_FAILED
		      WK_ERR_UNRECOVERABLE_ERROR
		      WK_ERR_REQUEST_TOKEN_STALE
		      WK_ERR_WEBAUTH_SERVER_ERROR
		      WK_ERR_LOGIN_FORCED
		      WK_ERR_USER_REJECTED
		      WK_ERR_CREDS_EXPIRED
                      WK_ERR_MULTIFACTOR_REQUIRED
                      WK_ERR_MULTIFACTOR_UNAVAILABLE
                      WK_ERR_LOGIN_REJECTED
                      WK_ERR_LOA_UNAVAILABLE
		      );
    @EXPORT_OK   = ();
}

our @EXPORT_OK;

sub WK_SUCCESS                         () { 0;}
sub WK_ERR_USER_AND_PASS_REQUIRED      () { 1;}
sub WK_ERR_LOGIN_FAILED                () { 2;}
sub WK_ERR_UNRECOVERABLE_ERROR         () { 3;}
sub WK_ERR_REQUEST_TOKEN_STALE         () { 4;}
sub WK_ERR_WEBAUTH_SERVER_ERROR        () { 5;}
sub WK_ERR_LOGIN_FORCED                () { 6;}
sub WK_ERR_USER_REJECTED               () { 7;}
sub WK_ERR_CREDS_EXPIRED               () { 8;}
sub WK_ERR_MULTIFACTOR_REQUIRED        () { 9;}
sub WK_ERR_MULTIFACTOR_UNAVAILABLE     () {10;}
sub WK_ERR_LOGIN_REJECTED              () {11;}
sub WK_ERR_LOA_UNAVAILABLE             () {12;}

our @ErrorNames = qw(SUCCESS
		     USER_AND_PASS_REQUIRED
		     LOGIN_FAILED
		     UNRECOVERABLE_ERROR
		     REQUEST_TOKEN_STALE
		     WEBAUTH_SERVER_ERROR
		     LOGIN_FORCED
		     USER_REJECTED
                     MULTIFACTOR_REQUIRED
                     MULTIFACTOR_UNAVAILABLE
                     LOGIN_REJECTED
                     LOA_UNAVAILABLE);

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
    return 0 unless ref $e;
    return 0 if !$e->isa("WebKDC::WebKDCException");
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

  WK_SUCCESS
  WK_ERR_USER_AND_PASS_REQUIRED
  WK_ERR_LOGIN_FAILED
  WK_ERR_UNRECOVERABLE_ERROR
  WK_ERR_REQUEST_TOKEN_STATLE
  WK_ERR_WEBAUTH_SERVER_ERROR
  WK_ERR_LOGIN_FORCED
  WK_ERR_USER_REJECTED
  WK_ERR_CREDS_EXPIRED
  WK_ERR_MULTIFACTOR_REQUIRED
  WK_ERR_MULTIFACTOR_UNAVAILABLE
  WK_ERR_LOGIN_REJECTED
  WK_ERR_LOA_UNAVAILABLE

=over 4

=item WK_SUCCESS

This status code never comes back as part of an exception, though it might
be returned by a function that uses these status codes as return values.

=item WK_ERR_USER_AND_PASS_REQUIRED

This status code indicates that a function was called that required a
username and password. The user should be prompted for their username and
the function should be called again.

=item WK_ERR_LOGIN_FAILED

This status code indicates that a function was called that attempted to
validate the username and password and could not, due to an invalid user or
password. The user should be re-prompted for their username/password and the
function should be called again.

=item WK_ERR_UNRECOVERABLE_ERROR

This status code indicates that a function was called and an error occured
that can not be recovered from. If you are in the process of attempting to
log a user in, you have no choice but to display an error message to the
user and not prompt again.

=item WK_ERR_REQUEST_TOKEN_STALE

This status code indicates the user took too long to login, and the the
request token is too old to be used.

=item WK_ERR_WEBAUTH_SERVER_ERROR

This status code indicates something happened that most likely indicates the
webauth server that made the request is mis-configured and/or unauthorized
to make the request. It is similar to WK_ERR_UNRECOVERABLE_ERROR except that
the error message to the user should indicate that the problem is most
likely with the server that redirected them.

=item WK_ERR_LOGIN_FORCED

This status code indicates that a function was called that required a
username and password even if single sign-on credentials were available.
The user should be prompted for their username and password and the function
should be called again with that data.

=item WK_ERR_USER_REJECTED

This status code indicates that the authenticated principal was rejected
by the WebKDC configuration (usually because WebKdcPermittedRealms was set
and the realm of the principal wasn't in that list).

=item WK_ERR_CREDS_EXPIRED

This status code indicates that the principal we attempted to authenticate
to has an expired password.

=item WK_ERR_MULTIFACTOR_REQUIRED

This status code indicates that authentication was successful but that
authentication with a second factor is also required.  The user should be
prompted for their second factor and then the login reattempted with that
information plus the returned proxy tokens.

=item WK_ERR_MULTIFACTOR_UNAVAILABLE

This status code indicates that the desired site requires multifactor, but
the user does not have multifactor configured or does not have the correct
second factor to authenticate to that site.

=item WK_ERR_LOGIN_REJECT

This status code indicates that this user is not allowed to log on to that
site at this time for security reasons.  This is a transitory error; the
user may be permitted to authenticate later, or from a different location.
This error message is used for rejected logins from particular locations,
logins that appear to be from a compromised account, or accounts that have
been locked out due to too many failed logins.

=item WK_ERR_LOA_UNAVAILABLE

This status code indicates that the site requested a Level of Assurance
for the user's authentication that is higher than this user can provide,
either because of insufficient proof of identity available to the system
or due to an insufficiently strong configured authentication method.

=back

=head1 METHODS and FUNCTIONS

=over 4

=item match($exception[, $status])

This class function (not a method) returns true if the given $exception is a
WebKDC::WebKDCException. If $status is specified, then $exception->status()
will also be compared to $status.

=item new(status, message, wrapped_exception)

This method is used to created new WebKDC::WebKDCException objects.

=item status()

This method returns the WebKDC::WebKDCException status code for the
exception, which will be one of the WK_ERR_* codes.

=item message()

This method returns the error message that was used in the constructor.

=item error_code()

This method returns the WebKDC errorCode (if there was one).

=item verbose_message()

This method returns a verbose error message, which consists of the status
code, message, and any error code.

The verbose_message method is also called if the exception is used as a
string.

=back

=head1 AUTHOR

Roland Schemers (schemers@stanford.edu)

=head1 SEE ALSO

L<WebKDC>.

=cut
