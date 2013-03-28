# Utility class for webauth tests.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Parts from Russ Allbery <rra@stanford.edu>
# Copyright 2010, 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package Util;
require 5.006;

use strict;
use warnings;
use vars qw(@ISA @EXPORT $VERSION);

use WebAuth qw(3.00 WA_KEY_AES WA_AES_128);
use WebKDC::Config ();
use WebLogin;
use Template;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '2.00';

use Exporter ();
@ISA    = qw(Exporter);
@EXPORT = qw(contents get_userinfo remctld_spawn remctld_stop create_keyring
             getcreds default_weblogin init_weblogin);

##############################################################################
# General utility functions
##############################################################################

# Returns the username and password from a file that contains them both,
# each on one line.
sub get_userinfo  {
    my ($file) = @_;
    open (FILE, '<', $file) or die "cannot open $file: $!\n";
    my $username = <FILE>;
    my $password = <FILE>;
    close FILE;
    chomp ($username, $password);
    return ($username, $password);
}

# Returns the one-line contents of a file as a string, removing the newline.
sub contents {
    my ($file) = @_;
    open (FILE, '<', $file) or die "cannot open $file: $!\n";
    my $data = <FILE>;
    close FILE;
    chomp $data;
    return $data;
}

# Create and give default settings to a weblogin object.
# TODO: Remove and replace with init_weblogin in all places.
sub default_weblogin {

    # Load a version of the page templates that only prints out the vars.
    my %pages = (confirm  => 'confirm.tmpl',
                 pwchange => 'pwchange.tmpl',
                 error    => 'error.tmpl',
                );
    $WebKDC::Config::TEMPLATE_PATH         = 't/data/templates';
    $WebKDC::Config::TEMPLATE_COMPILE_PATH = 't/tmp/ttc';

    # Set up a query with some test data.
    $ENV{REQUEST_METHOD} = 'GET';
    my $query = CGI->new ({});

    # Set up the testing WebLogin object.
    my $weblogin = WebLogin->new;
    my $resp     = WebKDC::WebResponse->new;
    my $req      = WebKDC::WebRequest->new;
    $req->request_token('TestReqToken');
    $req->service_token('TestServiceToken');
    $weblogin->{response} = $resp;
    $weblogin->{request}  = $req;
    $weblogin->query($query);
    $weblogin->param('pages', \%pages);
    $weblogin->param('logging', 0);

    return $weblogin;
}

# Initialize the weblogin object, as we'll have to keep touching this over
# and again.
sub init_weblogin {
    my ($username, $password, $st_base64, $rt_base64, $pages) = @_;

    my $query = CGI->new ({});
    $query->request_method ('POST');
    $query->param ('username', $username);
    $query->param ('password', $password);
    $query->param ('ST', $st_base64);
    $query->param ('RT', $rt_base64);

    $WebKDC::Config::TEMPLATE_PATH         = 't/data/templates';
    $WebKDC::Config::TEMPLATE_COMPILE_PATH = 't/tmp/ttc';

    my $weblogin = WebLogin->new (QUERY  => $query,
                                  PARAMS => { pages => $pages });
    $weblogin->cgiapp_prerun;
    $weblogin->param ('debug', 0);
    $weblogin->param ('logging', 0);
    $weblogin->param ('script_name', '/login');

    # Normally set during WebKDC::request_token_request.
    $weblogin->{response}->return_url ('https://test.example.org/');
    $weblogin->{response}->subject ($username);
    $weblogin->{response}->requester_subject ('webauth/test3.testrealm.org@testrealm.org');
    $weblogin->{response}->response_token ('TestResponse');
    $weblogin->{response}->response_token_type ('id');

    # Set the password expiration time depending on the user.
    if ($username eq 'testuser1') {
        # Expires in-range for a warning.
        $weblogin->{response}->password_expiration (time + 60 * 60 * 24);
    } elsif ($username eq 'testuser2') {
        # Expires out of range for a warning.
        $weblogin->{response}->password_expiration (time +
                                                    60 * 60 * 24 * 356);
    } elsif ($username eq 'testuser3') {
        # Do nothing here, we want non-existing pw expiration.
    } else {
        # Expires in-range for a warning..
        $weblogin->{response}->password_expiration (time + 60 * 60 * 24);
    }

    return $weblogin;
}

##############################################################################
# Kerberos utility functions
##############################################################################

# Given a keytab file and a principal, try authenticating with kinit.
sub getcreds {
    my ($file, $principal) = @_;
    my @commands = (
        "kinit -k -t $file $principal >/dev/null 2>&1 </dev/null",
        "kinit -t $file $principal >/dev/null 2>&1 </dev/null",
        "kinit -T /bin/true -k -K $file $principal >/dev/null 2>&1 </dev/null",
    );
    for my $command (@commands) {
        if (system ($command) == 0) {
            return 1;
        }
    }
    return 0;
}

# Given keytab data and the principal, write it to a file and try
# authenticating using kinit.
sub keytab_valid {
    my ($keytab, $principal) = @_;
    open (KEYTAB, '>', 'keytab') or die "cannot create keytab: $!\n";
    print KEYTAB $keytab;
    close KEYTAB;
    $principal .= '@' . $Wallet::Config::KEYTAB_REALM
        unless $principal =~ /\@/;
    my $result = getcreds ('keytab', $principal);
    if ($result) {
        unlink 'keytab';
    }
    return $result;
}

# Create a keyring file for use by the server.
sub create_keyring {
    my ($fname) = @_;
    return if -f $fname;

    my $wa = WebAuth->new;
    my $key = $wa->key_create (WA_KEY_AES, WA_AES_128);
    my $ring = $wa->keyring_new ($key);
    $ring->write ($fname);
}

##############################################################################
# remctld handling
##############################################################################

# Start remctld with the appropriate options to run our fake keytab backend.
# Takes the path to remctld, the principal it uses as its server principal,
# the keytab it uses for authentication, and the configuration file it should
# load.
sub remctld_spawn {
    my ($path, $principal, $keytab, $config) = @_;
    unlink 'test-pid';
    my @command = ($path, '-m', '-p', 14373, '-s', $principal, '-P',
                   'test-pid', '-f', $config, '-S', '-F', '-k', $keytab);
    print "Starting remctld: @command\n";
    my $pid = fork;
    if (not defined $pid) {
        die "cannot fork: $!\n";
    } elsif ($pid == 0) {
        open (STDERR, '>&STDOUT') or die "cannot redirect stderr: $!\n";
        exec (@command) or die "cannot exec $path: $!\n";
    } else {
        my $tries = 0;
        while ($tries < 10 && ! -f 'test-pid') {
            select (undef, undef, undef, 0.25);
        }
    }
}

# Stop the running remctld process.
sub remctld_stop {
    open (PID, '<', 'test-pid') or return;
    my $pid = <PID>;
    close PID;
    chomp $pid;
    kill 15, $pid;
}
