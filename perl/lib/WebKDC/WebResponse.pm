# An object encapsulating a response from a WebKDC.
#
# Written by Roland Schemers
# Copyright 2002, 2003, 2009, 2012, 2013, 2014
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

package WebKDC::WebResponse;

use strict;
use warnings;

our $VERSION;

# This version matches the version of WebAuth with which this module was
# released, but with two digits for the minor and patch versions.
BEGIN {
    $VERSION = '4.0700';
}

# Create a new, empty request.
sub new {
    my ($type) = @_;
    my $self = {};
    bless ($self, $type);
    return $self;
}

# Shared code for all simple accessor methods.  Takes the object, the
# attribute name, and the value.  Sets the value if one was given, and returns
# the current value of that attribute.
sub _attr {
    my ($self, $attr, $value) = @_;
    $self->{$attr} = $value if defined ($value);
    return $self->{$attr};
}

# Simple accessor methods.
sub app_state            { my $r = shift; $r->_attr ('app_state',         @_) }
sub default_device       { my $r = shift; $r->_attr ('default_device',    @_) }
sub default_factor       { my $r = shift; $r->_attr ('default_factor',    @_) }
sub login_canceled_token { my $r = shift; $r->_attr ('lc_token',          @_) }
sub return_url           { my $r = shift; $r->_attr ('return_url',        @_) }
sub subject              { my $r = shift; $r->_attr ('subject',           @_) }
sub authz_subject        { my $r = shift; $r->_attr ('authz_subject',     @_) }
sub requester_subject    { my $r = shift; $r->_attr ('requester_subject', @_) }
sub password_expiration  { my $r = shift; $r->_attr ('pwd_expiration',    @_) }
sub response_token       { my $r = shift; $r->_attr ('response_token',    @_) }
sub user_message         { my $r = shift; $r->_attr ('user_message',      @_) }
sub login_state          { my $r = shift; $r->_attr ('login_state',       @_) }
sub response_token_type {
    my $r = shift;
    $r->_attr ('response_token_type', @_);
}

# Set or return the list of permitted authorization identities.
sub permitted_authz {
    my ($self, @values) = @_;
    if (@values) {
        $self->{permitted_authz} = [ @values ];
    } else {
        $self->{permitted_authz} ||= [];
    }
    return @{ $self->{permitted_authz} };
}

# Cookies are stored by type in a hash with value and (optional) expiration.
# Use cookies to retrieve the complete hash of cookies.
sub cookie {
    my ($self, $type, $value, $expiration) = @_;
    if (defined $value) {
        if (!defined $expiration) {
            $expiration = 0;
        }
        $self->{cookies}{$type}{value}      = $value;
        $self->{cookies}{$type}{expiration} = $expiration;
    }

    if (exists $self->{cookies}{$type}) {
        return $self->{cookies}{$type}{value};
    } else {
        return undef;
    }
}

# Return the cookies as a hash.
sub cookies {
    my ($self) = @_;
    return $self->{cookies};
}

# Login history, needed and configured factors, and devices are stored in
# arrays.  Note that there is no way of clearing the array once a value has
# been set, only adding new values.
sub devices {
    my ($self, @values) = @_;
    push (@{ $self->{devices} }, @values) if @values;
    return $self->{devices};
}
sub factor_configured {
    my ($self, @values) = @_;
    push (@{ $self->{'factor_configured'} }, @values) if @values;
    return $self->{'factor_configured'};
}
sub factor_needed {
    my ($self, @values) = @_;
    push (@{ $self->{'factor_needed'} }, @values) if @values;
    return $self->{'factor_needed'};
}
sub login_history {
    my ($self, @values) = @_;
    push (@{ $self->{'login_history'} }, @values) if @values;
    return $self->{'login_history'};
}

1;

__END__

=for stopwords
WebAuth WebKDC login WEBAUTHS multifactor WEBAUTHR IP hostname webkdc-proxy
WebLogin Allbery

=head1 NAME

WebKDC::WebResponse - Encapsulates a response from a WebAuth WebKDC

=head1 SYNOPSIS

    use WebKDC::WebResponse

    my $resp = WebKDC::WebResponse->new;
    $resp->subject ($user);
    $resp->requester_subject ($req_subject);
    $resp->response_token_type ('id');
    $resp->response_token ($id);
    $resp->return_url ($url);

=head1 DESCRIPTION

A WebKDC::WebResponse object encapsulates a response from a WebAuth
WebKDC, representing the result of a login attempt for a particular
WebAuth Application Server.  It is filled in by the WebKDC module as the
result of a make_request_token_request call.  The object has very little
inherent functionality.  It's mostly a carrier for data.

=head1 CLASS METHODS

=over 4

=item new ()

Create a new, empty WebKDC::WebResponse object.  At least some parameters
must be set using accessor functions as described below to do anything
useful with the object.

=back

=head1 INSTANCE METHODS

=over 4

=item app_state ([STATE])

Returns or sets the application state token.  If this is set in the
response, the WebLogin server should return it to the WebAuth application
server as the WEBAUTHS parameter in the URL.

=item authz_subject ([SUBJECT])

Retrieve or set the asserted authorization identity.  This is an identity
separate from the authentication identity that is vetted by the WebKDC and
asserted for authorization purposes to the remote site.  It is included in
the id or proxy token, but is also included directly in the response for
display reasons in the WebLogin code.

=item default_device ([ID])

Returns or sets the default device to use for obtaining a second factor.
This may be set when the user's authentication was rejected because
multifactor authentication was required, and is used by WebLogin as part
of the prompting for the second factor authentication.

=item default_factor ([FACTOR])

Returns or sets the default authentication factor to use when a second
authentication factor besides password is required.  This may be set when
the user's authentication was rejected because multifactor authentication
was required, and is used by WebLogin as part of the prompting for the
second factor authentication.

=item devices ([RECORD, ...])

Returns the list of devices for second authentication factors that the
user has available, or adds a new one.  If any parameters are given, they
are device records that will be added to the list.  Note that there is no
way to remove an entry from the list once it has been added.

Each RECORD should be an anonymous hash with a C<name> key indicating the
human-readable name of the device, a C<id> key indicating the opaque
identifier for the device, and a C<factors> key, whose value is a
reference to an array of factor codes that device supports.  The
default_device() attribute should match the C<id> key of one of the device
records, and the default_factor() attribute should match one of the factors
listed for that device.

=item factor_configured ([FACTOR, ...])

=item factor_needed ([FACTOR, ...])

Returns or sets the authentication factors this user has configured or
that the WebAuth application server requires.  These are set when the
user's authentication was rejected because multifactor authentication was
required and are used by the WebLogin server to determine what factor to
prompt for or to customize an error message explaining to the user what
factors they need to configure.

=item login_canceled_token ([LC])

Returns or sets a login cancellation token.  If the user decides to cancel
this authentication, this token should be returned to the WebAuth
application server as the WEBAUTHR parameter in the URL.

=item login_history ([RECORD, ...])

Returns the list of login history records or adds new login history
records.  If any parameters are given, they are history records that will
be added to the list.  Note that there is no way to remove an entry from
the list once it has been added.

Each RECORD should be an anonymous hash with an C<ip> key whose value is
the IP address from which the user logged in and a C<timestamp> key whose
value is the time of that login in seconds since epoch.  There may
optionally be a C<hostname> key that, if present, gives the hostname from
which the user logged in.

=item permitted_authz ([SUBJECT, ...])

Returns the list of permitted authorization identities or sets them.  If
any parameters are given, the list of acceptable authorization identities
is replaced with the list of subjects given.  The permitted authorization
identities are unique to this authenticated user and destination site.

=item cookie (TYPE[, VALUE][, EXPIRATION])

Returns or sets a cookie of the specified type.  The TYPE parameter should
be the type of the cookie.  The VALUE, if present, is the corresponding
token, suitable for being set as a browser cookie.  The EXPIRATION, if
present, is the value the cookie expiration should be set for.  Returns
the token of the given type, if any is set.

=item cookies ()

Returns all cookies as a hash, whose keys are the types and whose values
are the tokens.  The returned hash is a reference to the hash inside the
WebKDC::WebResponse object and therefore should not be modified by the
caller.

=item return_url ([URL])

Returns or sets the return URL to which the user should be directed after
authentication.

=item requester_subject ([SUBJECT])

Returns or sets the identity of the WebAuth application server that
prompted this authentication attempt.

=item response_token ([TOKEN])

=item response_token_type ([TYPE])

Returns or sets the token that is the result of the authentication
attempt, or the type of that token.  This will be either an id token or a
proxy token, depending on what the WebAuth application server requested.

=item subject ([SUBJECT])

Returns or sets the authenticated user identity.

=item password_expiration ([EXPIRATION])

Returns or sets the password expiration time for the authenticating user,
in seconds since UNIX epoch.

=item user_message ([TEXT])

Text passed back from the user information service as a message to
display to the user as explanatory text.

=back

=head1 AUTHOR

Roland Schemers and Russ Allbery <eagle@eyrie.org>

=head1 SEE ALSO

WebKDC(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
