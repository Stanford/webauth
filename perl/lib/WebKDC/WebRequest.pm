# An object encapsulating a request to a WebKDC.
#
# Written by Roland Schemers
# Copyright 2002, 2003, 2005, 2009, 2012, 2013, 2014
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

package WebKDC::WebRequest;

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
sub authz_subject  { my $r = shift; $r->_attr ('authz_subject',  @_) }
sub device_id      { my $r = shift; $r->_attr ('device_id',      @_) }
sub local_ip_addr  { my $r = shift; $r->_attr ('local_ip_addr',  @_) }
sub local_ip_port  { my $r = shift; $r->_attr ('local_ip_port',  @_) }
sub otp            { my $r = shift; $r->_attr ('otp',            @_) }
sub otp_type       { my $r = shift; $r->_attr ('otp_type',       @_) }
sub login_state    { my $r = shift; $r->_attr ('login_state',    @_) }
sub pass           { my $r = shift; $r->_attr ('pass',           @_) }
sub remote_ip_addr { my $r = shift; $r->_attr ('remote_ip_addr', @_) }
sub remote_ip_port { my $r = shift; $r->_attr ('remote_ip_port', @_) }
sub remote_user    { my $r = shift; $r->_attr ('remote_user',    @_) }
sub request_token  { my $r = shift; $r->_attr ('request_token',  @_) }
sub service_token  { my $r = shift; $r->_attr ('service_token',  @_) }
sub factor_token   { my $r = shift; $r->_attr ('factor_token',   @_) }
sub user           { my $r = shift; $r->_attr ('user',           @_) }

# Set or retrieve a proxy cookie of a particular type.  If given two
# arguments, returns the proxy cookie for that type.  If given four arguments,
# sets the proxy cookie and its corresponding session factor for that type.
sub proxy_cookie {
    my ($self, $type, $cookie, $factor) = @_;
    if (defined $cookie) {
        $self->{cookies}{$type}{cookie} = $cookie;
        $self->{cookies}{$type}{session_factor} = $factor;
    }
    return $self->{cookies}{$type};
}

# Set or retrieve a hash of all cookies.  The returned hash maps a cookie type
# to the proxy cookie.  If given a hash as a third argument, this should have
# the same structure as the internal proxy cookie hash: each type maps to an
# anonymous hash with two keys, cookie and session_factor.
sub proxy_cookies {
    my ($self, $cookies) = @_;
    $self->{cookies} = $cookies if defined $cookies;
    my %cookies;
    for my $type (keys %{ $self->{cookies} }) {
        $cookies{$type} = $self->{cookies}{$type}{cookie};
    }
    return \%cookies;
}

# Set or retrieve the hash of all cookies, including the session factors.
# This returns the same format as is used internally.
sub proxy_cookies_rich {
    my ($self, $cookies) = @_;
    $self->{'cookies'} = $cookies if $cookies;
    return $self->{'cookies'};
}

1;

__END__

=for stopwords
WebAuth WebKDC login IP otp username decrypt WebLogin Allbery multifactor
ADDR

=head1 NAME

WebKDC::WebRequest - Encapsulates a request to a WebAuth WebKDC

=head1 SYNOPSIS

    use WebKDC::WebRequest;

    my $req = WebKDC::WebRequest->new;
    $req->user ($user);
    $req->pass ($password);
    $req->request_token ($RT);
    $req->service_token ($ST);

=head1 DESCRIPTION

A WebKDC::WebRequest object encapsulates a request to a WebAuth WebKDC,
representing a login attempt for a particular WebAuth Application Server.
It is used by the WebLogin server as the argument to
make_request_token_request.  The object has very little inherent
functionality.  It's mostly a carrier for data.

=head1 CLASS METHODS

=over 4

=item new ()

Create a new, empty WebKDC::WebRequest object.  At least some parameters
must be set using accessor functions as described below to do anything
useful with the object.

=back

=head1 INSTANCE METHODS

=over 4

=item authz_subject ([USER])

Retrieve or set the requested authorization identity.  This is an identity
that the user wishes to assert for authorization purposes to the remote
site.  It must be vetted by the WebKDC and will be included in the id or
proxy token if asserting that authorization identity is permitted.

=item device_id ([ID])

Retrieve or set the ID of the device used for second factor
authentication.  This attribute is required if neither otp() nor pass()
are set.  It is used primarily to indicate a device with which the user is
performing an out-of-band second factor authentication that doesn't
involve a password or an OTP code.

=item local_ip_addr ([ADDR])

=item local_ip_port ([PORT])

=item remote_ip_addr ([ADDR])

=item remote_ip_port ([PORT])

Retrieve or set information about the network connection that is
attempting authentication.  If one of these values is set, all of them
should be set.  The remote_* parameters are the IP address of the remote
client that is attempting to authenticate, and the local_* parameters are
the local interface and port to which that client connected.

=item otp ([CODE])

Retrieve or set the one-time password sent by the user.  This, pass(),
or device_id() should be set, but otp() and pass() cannot both be set.

=item otp_type ([CODE])

Retrieve or set the one-time password type sent by the user.  Despite the
name, this can also be used with device_id() to specify the factor type
used for out-of-band device authentication, even if it doesn't involve
OTP.  This should be a WebAuth factor code corresponding to the type of
one-time password that this login token represents.  It may be left unset
if the caller doesn't know.

=item login_state ([STATE])

Get or set the login state of the request.  This field can contain any
data the implementer chooses to place and will be passed, by the WebKDC,
to the user information service as part of an OTP validation.  It is
usually used in conjunction with multifactor authentication to provide
some additional data about the type of multifactor being used.  It may be
left unset if unneeded.

=item pass ([PASSWORD])

Retrieve or set the password sent by the user.  Either this or otp should
be set, but not both.

=item proxy_cookie (TYPE[, COOKIE, FACTOR])

Retrieve or set a proxy cookie of a particular type.  If COOKIE and FACTOR
are given, sets a cookie of the given TYPE with value COOKIE and session
factor FACTOR.  Returns the cookie value of the given TYPE or undef if no
such cookie is available.

=item proxy_cookies ([COOKIES])

Retrieve or set a hash of all cookies.  If the COOKIES parameter is
provided, it must be a hash of cookie types to anonymous hashes, with each
value hash having two keys: C<cookie>, whose value is the cookie value,
and C<session_factor>, whose value is the session factors for that cookie.
Returns a hash of cookie types to values without the factor information.

=item proxy_cookies_rich ([COOKIES])

Retrieve or set a hash of all cookies including session factors.  If the
COOKIES parameter is provided, it must be a hash of cookie types to
anonymous hashes, with each value hash having two keys: C<cookie>, whose
value is the cookie value, and C<session_factor>, whose value is the
session factors for that cookie.  Returns a hash in the same structure as
the COOKIES argument.

=item remote_user ([USER])

Retrieve or set the remote username, as determined by some external
authentication system such as Apache authentication.  This is not
currently used.

=item request_token ([TOKEN])

Retrieve or set the request token from the WebAuth application server that
prompted this authentication request.  This must be set to create a valid
WebKDC::WebRequest.

=item service_token ([TOKEN])

Retrieve or set the service token provided by the WebAuth application
server, which contains the key used to decrypt the request token.  This
must be set to create a valid WebKDC::WebRequest.

=item factor_token ([TOKEN])

Retrieve or set the factor token, which contains a token given to the
user's device in an earlier login to denote a successful multifactor
login with that device.

=item user ([USER])

Retrieve or set the username of the authenticating user.  This must be set
to create a valid WebKDC::WebRequest.

=back

=head1 AUTHOR

Roland Schemers and Russ Allbery <eagle@eyrie.org>

=head1 SEE ALSO

WebKDC(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
