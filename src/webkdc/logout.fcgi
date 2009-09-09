#!/usr/bin/perl -w
our $ID = q($Id: logout.fcgi 3175 2007-04-24 01:26:28Z rra $ );
#
# logout.fcgi -- Weblogin logout page for WebAuth.
#
# Written by Jeanmarie Lucker <jlucker@stanford.edu>
# Copyright 2002, 2003, 2004 Board of Trustees, Leland Stanford Jr. University
#
# This is the logout page for weblogin authentication.  It doesn't do anything
# at present except destroy the proxy tokens and display a web page.
#
# It should use FastCGI if available, using the Perl CGI::Fast module's
# ability to fall back on regular operation if FastCGI isn't available.

use strict;

use CGI::Cookie ();
use CGI::Fast ();
use HTML::Template ();
use WebKDC::Config ();

# The name of the template to use for logout.
our $TEMPLATE = 'logout.tmpl';

# The HTML::Template object for the logout page.  When running under FastCGI,
# precompiling results in a significant speedup, since loading and compiling
# the templates is a bit time-consuming.
our $PAGE = HTML::Template->new (filename => $TEMPLATE, cache => 1,
                                 path => $WebKDC::Config::TEMPLATE_PATH);

# The main loop.  If we're not running under FastCGI, CGI::Fast will detect
# that and only run us through the loop once.  Otherwise, we live in this
# processing loop until the FastCGI socket closes.
while (my $q = new CGI::Fast) {
    my %cookies = fetch CGI::Cookie;
    my $ca;

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
        $PAGE->param (cookies_flag => 1);
        print $q->header (-type => 'text/html', -Pragma => 'no-cache',
                          -Cache_Control => 'no-cache, no-store',
                          -cookie => $ca);
    } else {
        print $q->header (-type => 'text/html', -Pragma => 'no-cache',
                          -Cache_Control => 'no-cache, no-store');
    }
    print $PAGE->output;

# Done on each pass through the FastCGI loop.  Clear out template parameters
# for all of the pages for the next run and restart the script if its
# modification time has changed.
} continue {
    $PAGE->clear_params;
    exit if -M $ENV{SCRIPT_FILENAME} < 0;
}
