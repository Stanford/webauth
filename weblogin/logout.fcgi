#!/usr/bin/perl -w
#
# logout.fcgi -- WebLogin logout page for WebAuth.
#
# This is the logout page for weblogin authentication.  It doesn't do anything
# at present except destroy the proxy tokens and display a web page.
#
# It should use FastCGI if available, using the Perl CGI::Fast module's
# ability to fall back on regular operation if FastCGI isn't available.
#
# Written by Jeanmarie Lucker <jlucker@stanford.edu>
# Copyright 2002, 2003, 2004, 2009, 2011
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;

use CGI::Cookie ();
use CGI::Fast ();
use WebKDC::Config ();
use WebLogin ();

# The name of the template to use for logout.
our %PAGES = (login    => 'login.tmpl',
              logout   => 'logout.tmpl',
              confirm  => 'confirm.tmpl',
              pwchange => 'pwchange.tmpl',
              error    => 'error.tmpl');

# The main loop.  If we're not running under FastCGI, CGI::Fast will detect
# that and only run us through the loop once.  Otherwise, we live in this
# processing loop until the FastCGI socket closes.
while (my $q = new CGI::Fast) {
    $q->param ('rm', 'logout') unless defined $q->param ('rm');
    my $weblogin = WebLogin->new (PARAMS => { pages => \%PAGES },
                                  QUERY  => $q);
    $weblogin->run;

# Done on each pass through the FastCGI loop.  Restart the script if its
# modification time has changed.
} continue {
    exit if -M $ENV{SCRIPT_FILENAME} < 0;
}
