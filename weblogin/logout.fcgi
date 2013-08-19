#!/usr/bin/perl
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
# Converted to CGI::Application by Jon Robertson <jonrober@stanford.edu>
# Copyright 2002, 2003, 2004, 2009, 2011, 2012, 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use CGI::Fast;
use WebLogin;

# Set to true in our signal handler to indicate that the script should exit
# once it finishes processing the current request.
our $EXITING = 0;

# Ignore SIGPIPE to force return of a proper error message.
local $SIG{PIPE} = 'IGNORE';

# The names of the page templates, relative to the template path configured in
# the WebLogin configuration file.  This is set in this driver so that a
# modified driver script can use different template names, allowing multiple
# login interfaces with different UIs.
our %PAGES = (
    login       => 'login.tmpl',
    logout      => 'logout.tmpl',
    confirm     => 'confirm.tmpl',
    pwchange    => 'pwchange.tmpl',
    multifactor => 'multifactor.tmpl',
    error       => 'error.tmpl',
);

# Create the persistent WebLogin object.
my $weblogin = WebLogin->new(PARAMS => { pages => \%PAGES });

# The main loop.  If we're not running under FastCGI, CGI::Fast will detect
# that and only run us through the loop once.  Otherwise, we live in this
# processing loop until the FastCGI socket closes, we get a signal to exit,
# or the script modification time changes.
while (my $q = CGI::Fast->new()) {
    local $SIG{TERM} = sub { $EXITING = 1 };

    # Set the default run mode for the logout script.
    if (!defined $q->param('rm')) {
        $q->param('rm', 'logout');
    }

    # Invoke the WebLogin application.
    $weblogin->query($q);
    $weblogin->run();
} continue {
    if ($EXITING || -M $ENV{SCRIPT_FILENAME} < 0) {
        exit;
    }
}
