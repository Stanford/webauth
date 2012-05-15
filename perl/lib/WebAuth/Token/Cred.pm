# Perl representation of a WebAuth cred token.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebAuth::Token::Cred;

require 5.006;
use strict;
use warnings;

use base qw(WebAuth::Token);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION = '1.00';

# Accessor methods.
sub subject    ($;$) { my $t = shift; $t->_attr ('subject',    @_) }
sub type       ($;$) { my $t = shift; $t->_attr ('type',       @_) }
sub service    ($;$) { my $t = shift; $t->_attr ('service',    @_) }
sub data       ($;$) { my $t = shift; $t->_attr ('data',       @_) }
sub creation   ($;$) { my $t = shift; $t->_attr ('creation',   @_) }
sub expiration ($;$) { my $t = shift; $t->_attr ('expiration', @_) }

1;
