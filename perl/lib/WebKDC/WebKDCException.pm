# Exception class for WebKDC call failures.
#
# Written by Roland Schemers
# Copyright 2002, 2003, 2005, 2006, 2008, 2009, 2011, 2012, 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

package WebKDC::WebKDCException;

use 5.008;

use strict;
use warnings;

use base qw(Exporter);
use overload '""' => \&to_string;

our $VERSION;

# This version matches the version of WebAuth with which this module was
# released, but with two digits for the minor and patch versions.
BEGIN {
    $VERSION = '4.0700';
}

# Export the error codes.  This list MUST be kept in sync and follow the same
# order as the sequence number of the error codes defined below in the
# constant subs or we won't map errors to the correct name.
our @EXPORT;
BEGIN {
    @EXPORT = qw(WK_SUCCESS
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
                 WK_ERR_AUTH_REJECTED
                 WK_ERR_AUTH_REPLAY
                 WK_ERR_AUTH_LOCKOUT
                 WK_ERR_LOGIN_TIMEOUT);
}

# This hash maps the error codes to names, used when stringifying.
our %ERROR_NAMES;
{
    my $i = 0;
    %ERROR_NAMES = map {
        my $n = $_;
        $n =~ s/^WK_(?:ERR_)?//;
        $i++ => $n;
    } @EXPORT;
}

# The error code constants.
sub WK_SUCCESS                     () {  0 }
sub WK_ERR_USER_AND_PASS_REQUIRED  () {  1 }
sub WK_ERR_LOGIN_FAILED            () {  2 }
sub WK_ERR_UNRECOVERABLE_ERROR     () {  3 }
sub WK_ERR_REQUEST_TOKEN_STALE     () {  4 }
sub WK_ERR_WEBAUTH_SERVER_ERROR    () {  5 }
sub WK_ERR_LOGIN_FORCED            () {  6 }
sub WK_ERR_USER_REJECTED           () {  7 }
sub WK_ERR_CREDS_EXPIRED           () {  8 }
sub WK_ERR_MULTIFACTOR_REQUIRED    () {  9 }
sub WK_ERR_MULTIFACTOR_UNAVAILABLE () { 10 }
sub WK_ERR_LOGIN_REJECTED          () { 11 }
sub WK_ERR_LOA_UNAVAILABLE         () { 12 }
sub WK_ERR_AUTH_REJECTED           () { 13 }
sub WK_ERR_AUTH_REPLAY             () { 14 }
sub WK_ERR_AUTH_LOCKOUT            () { 15 }
sub WK_ERR_LOGIN_TIMEOUT           () { 16 }

# Create a new WebKDC::WebKDCException object and initialize the status,
# message, protocol error, and data.
sub new {
    my ($type, $status, $mesg, $pec, $data) = @_;
    my $self = {
        status => $status,
        mesg   => $mesg,
        pec    => $pec,
        data   => $data
    };
    bless ($self, $type);
    return $self;
}

# Basic accessors.
sub status     { my $self = shift; return $self->{status} }
sub message    { my $self = shift; return $self->{mesg}   }
sub error_code { my $self = shift; return $self->{pec}    }
sub data       { my $self = shift; return $self->{data}   }

# A full verbose message with all the information from the exception except
# the exception data.
sub verbose_message {
    my $self = shift;
    my $s = $self->{'status'};
    my $m = $self->{'mesg'};
    my $pec = $self->{'pec'};
    my $msg = 'WebKDC::WebKDCException ' . $ERROR_NAMES{$s} . ": $m";
    $msg .= ": WebKDC errorCode: $pec" if defined $pec;
    return $msg;
}

# The string conversion of this exception is the full verbose message.
sub to_string {
    my ($self) = @_;
    return $self->verbose_message;
}

1;

__END__

=for stopwords
WebKDC username login WebAuth WebKdcPermittedRealms multifactor logins
errorCode Allbery WebLogin

=head1 NAME

WebKDC::WebKDCException - Exceptions for WebKDC communications

=head1 SYNOPSIS

    use WebKDC;
    use WebKDC::WebKDCException;

    eval {
        # ...
        WebKDC::request_token_request($req, $resp);
        # ...
    };
    my $e = $@;
    if (ref $e and $e->isa ('WebKDC::WebKDCException')) {
        # you can call the following methods on a WebKDCException object:
        # $e->status()
        # $e->message()
        # $e->error_code()
        # $e->verbose_message()
    }

=head1 DESCRIPTION

Various WebKDC functions may return a WebKDC::WebKDCException object if
anything goes wrong.  This object encapsulates various information about
the error.

This module also defines the status codes returned by the WebKDC
functions.

=head1 CONSTANTS

The following constants are exported:

=over 4

=item WK_SUCCESS

This status code never comes back as part of an exception.  It is returned
for success.

=item WK_ERR_USER_AND_PASS_REQUIRED

This status code indicates that a function was called that required a
username and password. The user should be prompted for their username and
the function should be called again.

=item WK_ERR_LOGIN_FAILED

This status code indicates that a function was called that attempted to
validate the username and password and could not, due to an invalid user
or password.  The user should be re-prompted for their username/password
and the function should be called again.

=item WK_ERR_UNRECOVERABLE_ERROR

This status code indicates that a function was called and an error
occurred that can not be recovered from.  If you are in the process of
attempting to log a user in, you have no choice but to display an error
message to the user and not prompt again.

=item WK_ERR_REQUEST_TOKEN_STALE

This status code indicates the user took too long to login, and the the
request token is too old to be used.  The user should be told to retry the
action that caused them to be prompted for authentication.

=item WK_ERR_WEBAUTH_SERVER_ERROR

This status code indicates something happened that most likely indicates
the WebAuth server that made the request is misconfigured and/or
unauthorized to make the request.  It is similar to
WK_ERR_UNRECOVERABLE_ERROR except that the error message to the user
should indicate that the problem is most likely with the server that
redirected them.

=item WK_ERR_LOGIN_FORCED

This status code indicates that a function was called that required a
username and password even if single sign-on credentials were available.
The user should be prompted for their username and password and the
function should be called again with that data.

=item WK_ERR_USER_REJECTED

This status code indicates that the authenticated principal was rejected
by the WebKDC configuration (usually because WebKdcPermittedRealms was set
and the realm of the principal wasn't in that list).

=item WK_ERR_CREDS_EXPIRED

This status code indicates that the principal we attempted to authenticate
to has an expired password.  If possible, the user should be prompted to
change their password and then the operation retried.

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

=item WK_ERR_AUTH_REJECTED

This user is not permitted to authenticate to the desired destination
WebAuth Application Server at this time.  This may be due to local policy,
security limitations placed on the user, missing prerequisite actions that
the user must take (such as training or a usage agreement), or some other
local factor.

=item WK_ERR_AUTH_REPLAY

This authentication attempt appears to be a replay.  Replays may be
rejected as a security measure to protect against people who walked away
with a browser open and left the WebLogin form submission in the browser
cache.

=item WK_ERR_AUTH_LOCKOUT

This account has been locked out due to too many unsuccessful login
attempts.  The login should be retried later.

=item WK_ERR_LOGIN_TIMEOUT

There was a timeout while attempting to log in.  The login should be
retried, though multiple errors could mean a problem outside of WebAuth.

=back

=head1 CLASS METHODS

=over 4

=item new (STATUS, MESSAGE[, ERROR[, DATA]])

Create a new WebKDC::WebKDCException object.  STATUS is one of the status
constants defined above other than WK_SUCCESS.  MESSAGE is the error
message for the exception.  ERROR, if present, is a protocol error code
that caused the exception.  DATA, if present, is additional data about the
exception, currently used to carry the HTML error message to display to
the user if one is available.

=back

=head1 INSTANCE METHODS

=over 4

=item data ()

Returns the additional exception data (if there was any).

=item error_code ()

Returns the WebKDC protocol errorCode (if there was one).

=item message ()

Returns the error message that was passed to the constructor.

=item status ()

Returns the WebKDC::WebKDCException status code for the exception, which
will be one of the WK_ERR_* codes.

=item verbose_message ()

This method returns a verbose error message, which consists of the status
code, message, and any error code.

=item to_string ()

This method is called if the exception is used as a string.  It is a
wrapper around the verbose_message method.

=back

=head1 AUTHOR

Roland Schemers and Russ Allbery <eagle@eyrie.org>

=head1 SEE ALSO

WebKDC(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
