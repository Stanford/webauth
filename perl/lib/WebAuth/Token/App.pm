# Perl representation of a WebAuth app token.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebAuth::Token::App;

use strict;
use warnings;

use WebAuth qw(3.00);

# Constructor.
sub new {
    my $type = shift;
    my $self = {};
    bless ($self, $type);
    return $self;
}

# Shared code for all accessor methods.  Takes the object, the attribute name,
# and the value.  Sets the value if one was given, and returns the current
# value of that attribute.
sub _attr {
    my ($self, $attr, $value) = @_;
    $self->{$attr} = $value if defined ($value);
    return $self->{$attr};
}

# Accessor methods.
sub subject         { my $self = shift; $self->_attr ('subject',         @_) }
sub last_used       { my $self = shift; $self->_attr ('last_used',       @_) }
sub session_key     { my $self = shift; $self->_attr ('session_key',     @_) }
sub initial_factors { my $self = shift; $self->_attr ('initial_factors', @_) }
sub session_factors { my $self = shift; $self->_attr ('session_factors', @_) }
sub loa             { my $self = shift; $self->_attr ('loa',             @_) }
sub creation        { my $self = shift; $self->_attr ('creation',        @_) }
sub expiration      { my $self = shift; $self->_attr ('expiration',      @_) }

1;
