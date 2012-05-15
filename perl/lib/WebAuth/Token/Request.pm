# Perl representation of a WebAuth request token.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebAuth::Token::Request;

require 5.006;
use strict;
use warnings;

use base qw(WebAuth::Token);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION = '1.00';

# Accessor methods.
sub type            ($;$) { my $t = shift; $t->_attr ('type',            @_) }
sub auth            ($;$) { my $t = shift; $t->_attr ('auth',            @_) }
sub proxy_type      ($;$) { my $t = shift; $t->_attr ('proxy_type',      @_) }
sub state           ($;$) { my $t = shift; $t->_attr ('state',           @_) }
sub return_url      ($;$) { my $t = shift; $t->_attr ('return_url',      @_) }
sub options         ($;$) { my $t = shift; $t->_attr ('options',         @_) }
sub initial_factors ($;$) { my $t = shift; $t->_attr ('initial_factors', @_) }
sub session_factors ($;$) { my $t = shift; $t->_attr ('session_factors', @_) }
sub loa             ($;$) { my $t = shift; $t->_attr ('loa',             @_) }
sub command         ($;$) { my $t = shift; $t->_attr ('command',         @_) }
sub creation        ($;$) { my $t = shift; $t->_attr ('creation',        @_) }

1;
