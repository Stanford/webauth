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
# Copyright 2002, 2003, 2004
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;

use CGI::Cookie ();
use CGI::Fast ();
use Template ();
use WebKDC::Config ();

# The name of the template to use for logout.
our $TEMPLATE = 'logout.tmpl';

# Set up a template object, along with caching options to compile the
# templates to Perl code and recheck for updates in the source files every
# minute.
my $template = Template->new ({
                               STAT_TTL     => 60,
                               COMPILE_DIR  =>
                                   $WebKDC::Config::TEMPLATE_COMPILE_PATH,
                               COMPILE_EXT  => '.ttc',
                               INCLUDE_PATH => $WebKDC::Config::TEMPLATE_PATH,
                               });

# The main loop.  If we're not running under FastCGI, CGI::Fast will detect
# that and only run us through the loop once.  Otherwise, we live in this
# processing loop until the FastCGI socket closes.
while (my $q = new CGI::Fast) {
    my %cookies = fetch CGI::Cookie;
    my $ca;
    my %params;

    # Locate any webauth_wpt cookies and blow them away, by setting the same
    # cookie again with a null value and an expiration date in the past.
    for my $key (sort keys %cookies) {
        if ($key =~ /^webauth_wpt/) {
            my ($name) = split ('=', $cookies{$key});
            push (@$ca, $q->cookie(-name => $name, -value => '',
                                   -expires => '-1d', -secure => 1));
         }
    }
    if ($ca) {
        $params{cookies_flag} = 1;
        print $q->header (-type => 'text/html', -Pragma => 'no-cache',
                          -Cache_Control => 'no-cache, no-store',
                          -cookie => $ca);
    } else {
        print $q->header (-type => 'text/html', -Pragma => 'no-cache',
                          -Cache_Control => 'no-cache, no-store');
    }
    $template->process ($TEMPLATE, \%params);

# Done on each pass through the FastCGI loop.  Restart the script if its
# modification time has changed.
} continue {
    exit if -M $ENV{SCRIPT_FILENAME} < 0;
}
