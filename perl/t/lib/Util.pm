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
use vars qw(@ISA @EXPORT $VERSION);

use WebAuth qw(3.00 WA_AES_KEY WA_AES_128);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '2.00';

use Exporter ();
@ISA    = qw(Exporter);
@EXPORT = qw(contents get_userinfo remctld_spawn remctld_stop create_keyring
             getcreds);

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
    my $key = $wa->key_create (WA_AES_KEY, WA_AES_128);
    my $ring = $wa->keyring_from_key ($key);
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
