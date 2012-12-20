#!/usr/bin/perl
#
# Utility functions for the mod_webauthldap test suite.
#
# Written by Anton Ushakov
# Copyright 2003
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use CGI qw/:standard/;
use CGI::Cookie;

sub test_title {
    my ($num, $desc) = @_;
    print <<EOS;

<title>test $num</title>
<h2>test $num: $desc</h2>
<hr>

EOS
}

sub return_links {

    print <<EOS;
<br>
Click <a href="/tests/index.html">here</a> to return without logging out<br>
Click <a href="/tests/auth/logout">here</a> to logout and return<br>

EOS
}

sub unauth_return_links {

    print <<EOS;
<br>
Click <a href="/ldaptests/index.html">here</a> to return to tests<br>

EOS
}

sub do_test {
    my ($test, $result, $good, $bad) = @_;
    my $r = $result ? "PASS" : "<b>FAIL</b>";
    my $m = $result ? $good : "<b>$bad</b>";

    print "<tr>";
    print "<td>$test</td>";
    print "<td>$r</td>";
    print "<td>$m</td>";
}

sub begin_tests {
    my ($desc) = @_;

    print <<EOS;
<h2>$desc</h2>
<table border="1" cellpadding="3" >
<tr align=center>
  <th>Test</th>
  <th>Result</th>
  <th>Comment</th>
</tr>
EOS

}

sub end_tests {
    print "</table>";
}

sub varprefix_tests {

    my $WEBAUTH_TOKEN_CREATION = $ENV{'WEBAUTH_TOKEN_CREATION'};
    my $WEBAUTH_TOKEN_EXPIRATION = $ENV{'WEBAUTH_TOKEN_EXPIRATION'};
    my $WEBAUTH_USER = $ENV{'WEBAUTH_USER'};

    my $TEST_WEBAUTH_TOKEN_CREATION = $ENV{'TEST_WEBAUTH_TOKEN_CREATION'};
    my $TEST_WEBAUTH_TOKEN_EXPIRATION = $ENV{'TEST_WEBAUTH_TOKEN_EXPIRATION'};
    my $TEST_WEBAUTH_USER = $ENV{'TEST_WEBAUTH_USER'};


    print "<hr>\n";

    &begin_tests("Performing WebAuthVarPrefix tests");

    &do_test("TEST_WEBAUTH_USER",
	     $TEST_WEBAUTH_USER ne '',
	     "set to <b>$TEST_WEBAUTH_USER</b>",
	     "not set!");

    &do_test("WEBAUTH_USER == TEST_WEBAUTH_USER",
	     $WEBAUTH_USER eq $TEST_WEBAUTH_USER,
	     "they are equal",
	     "they are not equal!");

    &do_test("WEBAUTH_USER == TEST_WEBAUTH_USER",
	     $WEBAUTH_USER eq $TEST_WEBAUTH_USER,
	     "they are equal",
	     "they are not equal!");

    &do_test("WEBAUTH_TOKEN_CREATION == TEST_WEBAUTH_TOKEN_CREATION",
	     $WEBAUTH_TOKEN_CREATION == $TEST_WEBAUTH_TOKEN_CREATION,
	     "they are equal",
	     "they are not equal!");

    &do_test("WEBAUTH_TOKEN_EXPIRATION == TEST_WEBAUTH_TOKEN_EXPIRATION",
	     $WEBAUTH_TOKEN_EXPIRATION == $TEST_WEBAUTH_TOKEN_EXPIRATION,
	     "they are equal",
	     "they are not equal!");

    &end_tests;


    print "<hr>\n";
}

sub dump_stuff {

    my $WEBAUTH_TOKEN_CREATION = $ENV{'WEBAUTH_TOKEN_CREATION'};
    my $WEBAUTH_TOKEN_EXPIRATION = $ENV{'WEBAUTH_TOKEN_EXPIRATION'};
    my $WEBAUTH_USER = $ENV{'WEBAUTH_USER'};
    my $REMOTE_USER = $ENV{'REMOTE_USER'};
    my $AUTH_TYPE = $ENV{'AUTH_TYPE'};

    print "<hr>\n";

    &begin_tests("Performing standard tests");

    &do_test("AUTH_TYPE",
	     (($AUTH_TYPE eq 'WebAuth') or ($AUTH_TYPE eq 'StanfordAuth')),
	     "set to <b>$AUTH_TYPE</b>",
	     "not WebAuth, its $AUTH_TYPE");

    &do_test("REMOTE_USER",
	     $REMOTE_USER ne '',
	     "set to <b>$REMOTE_USER</b>",
	     "not set!");

    &do_test("WEBAUTH_USER",
	     $WEBAUTH_USER ne '',
	     "set to <b>$WEBAUTH_USER</b>",
	     "not set!");

    &do_test("WEBAUTH_USER == REMOTE_USER",
	     $WEBAUTH_USER eq $REMOTE_USER,
	     "they are equal",
	     "they are not equal!");

    &do_test("WEBAUTH_TOKEN_CREATION",
	     $WEBAUTH_TOKEN_CREATION ne '',
	     "set to <b>".scalar(localtime($WEBAUTH_TOKEN_CREATION))."</b>",
	     "not set!");

    &do_test("WEBAUTH_TOKEN_EXPIRATION",
	     $WEBAUTH_TOKEN_EXPIRATION ne '',
	     "set to <b>".scalar(localtime($WEBAUTH_TOKEN_EXPIRATION))."</b>",
	     "not set!");

    &end_tests;


    print "<hr>\n";

    print <<EOS;
<h2>WebAuth Cookies (set on the way in)</h2>
<table border="1" cellpadding="3" width="50%">
<tr align=center>
  <th>Name</th>
  <th>Value</th>
</tr>
EOS

my %cookies = CGI::Cookie->fetch;

foreach my $var (sort(keys(%cookies))) {
    next unless $var =~ /^webauth_/ && $var !~ /^webauth_wpt_/;
    my ($name, $val) = split('=', $cookies{$var});
    if (length($val) > 40) {
	$val = substr($val, 0, 40) . "...(truncated)";
    }

    $val = escapeHTML($val);
    print "<tr><td>${var}</td><td>${val}</td>\n";
}

print<<EOS; 

</table>
<hr>

<h2>Environment Variables</h2>
<table border="1" cellpadding="3" width="80%">
 <tr align=center>
  <th>Name</th>
 <th>Value</th>
 </tr>
EOS

foreach my $var (sort(keys(%ENV))) {

    my $val = $ENV{$var};
    if (length($val) > 80) {
	$val = substr($val, 0, 80) . "...(truncated)";
    }
    $val = escapeHTML($val);
    
#    $val =~ s|\n|\\n|g;
#    $val =~ s|"|\\"|g;

    print "<tr><td>$var</td><td>$val</td>\n";
}

print "</table>\n";

print "<hr>\n";

}

1;
