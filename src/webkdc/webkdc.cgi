#!/usr/pubsw/bin/perl

use strict;
use warnings;

#use blib '../bindings/perl/WebAuth';

use WebAuth;
use WebKDC;

sub dump_stuff {
    print "Content-type: text/plain\n\n";
    my ($var, $val);
    foreach $var (sort(keys(%ENV))) {
	$val = $ENV{$var};
	$val =~ s|\n|\\n|g;
	$val =~ s|"|\\"|g;
	print "${var}=\"${val}\"\n";
    }
    
    print "\n";
    print "\n";
    while(<STDIN>) {
	print "INPUT: $_";
    }
}

if ($ENV{'PATH_INFO'} eq '/dump') {
    dump_stuff;
} else {
    my $request;
    $request .= $_ while (<STDIN>);
    my $response = WebKDC::handle_xml_request($request);

    print "Content-type: text/xml\n\n";
    print $response;

}
