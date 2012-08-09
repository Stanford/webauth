#!/usr/bin/perl -w
#
# pwchange.fcgi -- WebLogin password change page for WebAuth.
#
# This is the page to change user password for weblogin.  It accepts
# information from the user, passes it to the WebKDC for authentication, and
# changes password if credentials match.
#
# It should use FastCGI if available, using the Perl CGI::Fast module's
# ability to fall back on regular operation if FastCGI isn't available.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010, 2011, 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

require 5.006;

use strict;

use CGI::Fast ();
use WebLogin ();

# Set to true in our signal handler to indicate that the script should exit
# once it finishes processing the current request.
our $EXITING = 0;

# The name of the template to use for logout.
our %PAGES = (login    => 'login.tmpl',
              logout   => 'logout.tmpl',
              confirm  => 'confirm.tmpl',
              pwchange => 'pwchange.tmpl',
              error    => 'error.tmpl');

##############################################################################
# Main routine
##############################################################################

# The main loop.  If we're not running under FastCGI, CGI::Fast will detect
# that and only run us through the loop once.  Otherwise, we live in this
# processing loop until the FastCGI socket closes.
while (my $q = CGI::Fast->new) {
    $SIG{TERM} = sub { $EXITING = 1 };
    $q->param ('rm', 'pwchange') unless defined $q->param ('rm');
    my $weblogin = WebLogin->new (PARAMS => { pages => \%PAGES },
                                  QUERY  => $q);
    $weblogin->run;
    $SIG{TERM} = 'DEFAULT';

# Done on each pass through the FastCGI loop.  Restart the script if its
# modification time has changed.
} continue {
    exit if $EXITING;
    exit if -M $ENV{SCRIPT_FILENAME} < 0;
}
