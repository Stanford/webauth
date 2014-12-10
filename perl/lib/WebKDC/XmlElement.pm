# Parse and manipulate XML documents and elements.
#
# Written by Roland Schemers
# Copyright 2002, 2009, 2012, 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

package WebKDC::XmlElement;

use strict;
use warnings;

use XML::Parser ();

our $VERSION;

# This version matches the version of WebAuth with which this module was
# released, but with two digits for the minor and patch versions.
BEGIN {
    $VERSION = '4.0700';
}

# An internaml method to convert the tree returned by XML::Parse into a tree
# of WebKDC::XmlElements rooted in the WebKDC::XmlElement passed as the first
# argument.  Calls itself recursively.
#
# This method destroys the contents of the tree argument.
sub _convert_tree {
    my ($root, $tree) = @_;
    $root->attrs (shift @$tree);
    my ($element, $content);
    while (defined ($element = shift @$tree)) {
        $content = shift @$tree;
        if ($element eq '0') {
            $root->append_content ($content) if ($content ne '');
        } elsif (ref $content eq 'ARRAY') {
            my $child = WebKDC::XmlElement->new;
            $child->name ($element);
            $child->_convert_tree ($content);
            $root->add_child ($child);
        } else {
            die "convert tree error: unknown tree content $content";
        }
    }
}

# Create a new WebKDC::XMLElement.
#
# If the optional argument is given, it is an XML document.  Parse that
# document into a tree of WebKDC::XMLElement objects.  Each object contains
# four attributes: name, attrs (a hash of the attributes), children (an array
# of the child elements), and content.
#
# For example:
#
#     <getTokensRequest>
#       <requesterCredential type="krb5">
#         {base64-krb5-mk-req-data}
#       </requesterCredential>
#       <tokens>
#         <token type="service" id="0"/>
#       </tokens>
#     </getTokensRequest>
#
# will parse into:
#
#     $tree = {
#       'name' => 'getTokensRequest'
#       'attrs' => {}
#       'children' => [
#           {
#             'name' => 'requesterCredential',
#             'attrs' => { 'type' => 'krb5' },
#             'content' => '    {base64-krb5-mk-req-data}  '
#           }
#           {
#              'name' => 'tokens',
#              'attrs' => {},
#              'children' => [
#                 {
#                   'name' => 'token',
#                   'attrs' => { 'id' => 0, 'type' => 'service'},
#                   'content' => '     '
#                 }
#              ]
#           }
#       ]
#       'content' => '      '
#     };
#
# with some minor variations in whitespace.  Note that all the whitespace in
# the document will get left in.  It should be trimmed if needed.
sub new {
    my ($type, $xml) = @_;
    my $self = { 'attrs' => {}, 'children' => [] };
    bless ($self, $type);
    if (defined $xml) {
        my $parser = XML::Parser->new (Style => 'Tree');
        my $tree = $parser->parse ($xml);
        $self->name (shift @$tree);
        $self->_convert_tree (shift @$tree);
    }
    return $self;
}

# Shared code for all simple accessor methods.  Takes the object, the
# attribute name, and the value.  Sets the value if one was given, and returns
# the current value of that attribute.
sub _attr {
    my ($self, $attr, $value) = @_;
    $self->{$attr} = $value if defined ($value);
    return $self->{$attr};
}

# Simple accessor functions.
sub attrs    { my $e = shift; $e->_attr ('attrs',    @_) };
sub children { my $e = shift; $e->_attr ('children', @_) };
sub content  { my $e = shift; $e->_attr ('content',  @_) };
sub name     { my $e = shift; $e->_attr ('name',     @_) };

# Returns the content trimmed of whitespace.
sub content_trimmed {
    my ($self) = @_;
    my $content = $self->content;
    return unless defined $content;
    $content =~ s/^\s+//;
    $content =~ s/\s+$//;
    return $content;
}

# Append additional content to this element.
sub append_content {
    my ($self, $content) = @_;
    $self->{content} = '' unless defined $self->{content};
    $self->{content} .= $content;
}

# Return true if this element has attributes or has children.
sub has_attrs    ($) { my $e = shift; return !!%{ $e->{attrs} } }
sub has_children ($) { my $e = shift; return $#{ $e->{children} } != -1 }

# Set or return a specific attribute.
sub attr {
    my ($self, $name, $value) = @_;
    $self->{attrs}{$name} = $value if defined $value;
    return $self->{attrs}{$name};
}

# Find and return the first child element with the given name, or undef if
# there is no such element.
sub find_child {
    my ($self, $name) = @_;
    for my $child (@{ $self->children }) {
        return $child if ($child->name eq $name);
    }
    return;
}

# Add the given WebKDC::XmlElement object as a child of this element.  It
# will be added after all the existing children.
sub add_child {
    my ($self, $element) = @_;
    push (@{ $self->{children} }, $element);
}

# Internal function to do XML escaping of a text string.  Returns the new
# value.
sub _escape {
    my ($self, $text) = @_;
    $text =~ s/&/&amp;/g;
    $text =~ s/</&lt;/g;
    $text =~ s/>/&gt;/g;
    $text =~ s/\"/&quot;/g;
    $text =~ s/\'/&apos;/g;
    return $text;
}

# Internal recursive function implementing the core of to_string.  Takes the
# element to turn to a string, a reference to the output string, a flag saying
# whether or not to pretty-print the output, and an indentation level (used
# only for pretty-printing).  Appends the output to the output buffer and
# returns nothing.
sub _recursive_to_string {
    my ($e, $out, $pretty, $level) = @_;
    my $name = $e->name;
    my $closed = 0;
    my $cont = 0;

    # Encode the open tag and the attributes.
    $$out .= ' ' x $level if $pretty;
    $$out .= "<$name";
    while (my ($attr, $val) = each %{ $e->attrs }) {
        $val = $e->_escape ($val);
        $$out .= qq( $attr="$val");
    }

    # Encode the content.
    if (defined $e->content) {
        unless ($closed) {
            $$out .= '>';
            $closed = 1;
        }
        $cont = 1;
        $$out .= $e->_escape ($e->content);
    }

    # Encode the child elements.
    for my $child (@{ $e->children }) {
        unless ($closed) {
            $$out .= '>';
            $$out .= "\n" if $pretty;
            $closed = 1;
        }
        $child->_recursive_to_string($out, $pretty, $level + 2);
    }

    # Close the tag.
    if ($closed) {
        $$out .= ' ' x $level if ($pretty && !$cont);
        $$out .= "</$name>";
        $$out .= "\n" if $pretty;
    } else {
        $$out .= ' />';
        $$out .= "\n" if $pretty;
    }
}

# Convert this element (and hence the whole document rooted at this element)
# into XML and return the result.  Tags a flag saying whether to pretty-print
# the output.
sub to_string {
    my ($self, $pretty) = @_;
    my $output;
    $self->_recursive_to_string (\$output, $pretty, 0);
    return $output;
}

1;

__END__

=for stopwords
WebKDC WebAuth attr attrs Allbery

=head1 NAME

WebKDC::XmlElement - Parse and manipulate XML documents and elements

=head1 SYNOPSIS

    use WebKDC::XmlElement;

    my $root = WebKDC::XmlElement->new ($xml);
    my $e = $root->find_child ('foo');
    my $content = $e->content_trimmed;
    print $root->to_string (1);

=head1 DESCRIPTION

A WebKDC::XmlElement object represents an XML element, including its
attributes, textual content, and any nested elements.  It therefore can
represent an entire XML document, although XML documents are normally
constructed via the methods provided by WebKDC::XmlDoc.  It is used
internally by the WebKDC module to create and parse XML documents when
talking to a WebAuth WebKDC.

=head1 CLASS METHODS

=over 4

=item new ([XML])

Create a new WebKDC::XmlElement.  If XML is given, do so by parsing that
XML using XML::Parser.  The resulting element will represent the complete
structure of that document, including any nested elements, any attributes,
and any non-element content.

=back

=head1 INSTANCE METHODS

=over 4

=item add_child (ELEMENT)

Add a WebKDC::XmlElement object as a child of this element.  It will be
appended to the end of the list of all existing children.

=item append_content (CONTENT)

Append the provided content to the textual content of this element.

=item attr (NAME[, VALUE])

Retrieve or set the value of a specific attribute.  Returns undef if that
attribute isn't present for this element.

=item attrs ([ATTRS])

Retrieve or set the attributes for this element (as a reference to an
anonymous hash).

=item children ([CHILDREN])

Retrieve or set the children of this element (as a reference to an
anonymous array of WebKDC::XmlElement objects).

=item content ([CONTENT])

Retrieve or set the textual content of this element as a string, not
including any child elements.  Returns undef if the element has no
content.

=item content_trimmed ()

Retrieve the textual content of this element with all leading and trailing
whitespace removed.  Returns undef if the element has no content.

=item find_child (NAME)

Returns the first child (as a WebKDC::XmlElement object) of this element
whose name matches NAME.

=item has_attrs ()

Returns true if this element has attributes, false otherwise.

=item has_children ()

Returns true if this element has children, false otherwise.

=item name ([NAME])

Retrieve or set the name of this element as a string.

=item to_string ()

Convert this XML element (and, recursively, all of its children) to XML.

=back

=head1 AUTHOR

Roland Schemers and Russ Allbery <eagle@eyrie.org>

=head1 SEE ALSO

WebKDC(3), WebKDC::XmlDoc(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
