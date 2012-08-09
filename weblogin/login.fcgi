#!/usr/bin/perl -w
#
# login.fcgi -- WebLogin login page for WebAuth.
#
# This is the front page for user authentication for weblogin.  It accepts
# information from the user, passes it to the WebKDC for authentication, sets
# appropriate cookies, and displays the confirmation page and return links.
#
# It should use FastCGI if available, using the Perl CGI::Fast module's
# ability to fall back on regular operation if FastCGI isn't available.
#
# Written by Roland Schemers <schemers@stanford.edu>
# Extensive updates by Russ Allbery <rra@stanford.edu>
# Converted to CGI::Application by Jon Robertson <jonrober@stanford.edu>
# Copyright 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2011, 2012
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
use WebKDC::Config ();

# Set to true in our signal handler to indicate that the script should exit
# once it finishes processing the current request.
our $EXITING = 0;

# The names of the template pages that we use.  The beginning of the main
# routine changes the values here to be Template Toolkit objects.
our %PAGES = (confirm     => 'confirm.tmpl',
              error       => 'error.tmpl',
              login       => 'login.tmpl',
              logout      => 'logout.tmpl',
              multifactor => 'multifactor.tmpl',
              pwchange    => 'pwchange.tmpl');

# If the WebKDC is localhost, disable LWP certificate verification.  The
# WebKDC will have a certificate matching its public name, which will never
# match localhost, and we should be able to trust the server when connecting
# directly to localhost.
if ($WebKDC::Config::URL =~ m,^https://localhost/,) {
    $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;
}

##############################################################################
# Main routine
##############################################################################

# The main loop.  If we're not running under FastCGI, CGI::Fast will detect
# that and only run us through the loop once.  Otherwise, we live in this
# processing loop until the FastCGI socket closes.
while (my $q = CGI::Fast->new) {
    $SIG{TERM} = sub { $EXITING = 1 };
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
