package WebKDC::XmlInputNode;

use strict;
use warnings;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;

sub new {
    my $type = shift;
    my $self = { 'name' => shift};
    if (@_) {
	$self->{'root'} = shift;
    }
    bless $self, $type;
    return $self;
}


package WebKDC::XmlInput;

use strict;
use warnings;

use XML::Parser;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;

sub convert_tree {
    my ($doc, $tree) = @_;
    $doc->{"attrs"} = shift @$tree;
    my ($element, $content);

    while (defined($element = shift @$tree)) {
	$content = shift @$tree;
	if ($element eq '0') {
	    $doc->{"content"} .= $content if $content ne '';
	} elsif (ref $content eq 'ARRAY') {
	    my $child = { "name" =>  $element };
	    convert_tree($child, $content);
	    push @{$doc->{'children'}}, $child;
	} else {
	    die "convert tree error";
	}
    }
};


# 
# parses XML into a hash of hashes, where 'name' is the name
# of the tag, 'attrs' is a hash of the attributes, 'children'
# is an array of the child elements, and 'content' is all of 
# the textual content.
# 
# for example:
# 
# <getTokensRequest>
#    <requesterCredential type="krb5">
#               {base64-krb5-mk-req-data}
#    </requesterCredential>
#   <tokens>
#     <token type="service" id="0"/>
#   </tokens>
# </getTokensRequest>
# 
# will parse into:
# 
# $tree = {
#   'name' => 'getTokensRequest'
#   'attrs' => {}
#   'children' => [
#       {
#         'name' => 'requesterCredential',
#         'attrs' => { 'type' => 'krb5' },
#         'content' => '   {base64-krb5-mk-req-data}  '
#       }
#       {
#          'name' => 'tokens',
#          'attrs' => {},
#          'children' => [
#             {
#               'name' => 'token',
#               'attrs' => { 'id' => 0, 'type' => 'service'},
#               'content' => '     '
#             }
#          ]
#       }
#   ]
#   'content' => '      '
# };
#
# note that all the whitespace in the document will get left
# in. It should be trim'd if needed.
#

sub parse {
    my ($xml) = @_;

    my $parser = new XML::Parser(Style => 'Tree');
    my $tree = $parser->parse($xml);
 
    my $doc = { "name" => shift @$tree };
    convert_tree($doc, shift @$tree);
    return $doc;
}

1;
