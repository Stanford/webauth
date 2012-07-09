# Manipulate a document composed of WebKDC::XmlElement objects.
#
# Written by Roland Schemers
# Copyright 2002, 2009, 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebKDC::XmlDoc;

use strict;
use warnings;

use Carp qw(croak);
use WebKDC::XmlElement;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION;
BEGIN {
    $VERSION = '1.01';
}

# Create a new, empty document.
sub new {
    my ($type) = @_;
    my $self = {};
    bless ($self, $type);
    return $self;
}

# Start a new document element.  Takes the name of the element, an optional
# hash of attributes, and optional content for the attribute.  If the document
# is currently empty, this will become the root element of the document.
sub start {
    my ($self, $name, $attrs, $content) = @_;
    my $element = WebKDC::XmlElement->new;
    $element->name ($name);
    if (defined $attrs) {
        $element->attrs ($attrs);
    }
    if (defined $content) {
        $element->content ($content);
    }
    if (defined $self->{root}) {
        my $parent = $self->current;
        $parent->add_child ($element);
    } else {
        $self->{root} = $element;
    }
    push (@{ $self->{stack} }, $element);
    return $self;
}

# Return the current open element.
sub current {
    my ($self) = @_;
    my $s = $self->{stack};
    my $e = @{ $s }[$#{ $s }] || croak ('not in an element');
    return $e;
}

# Close the currently open element.  Note that if this is called for the root
# element, no further elements can be added to the document.  Takes the
# optional name of the element to close.  If given, an exception will be
# raised if the current open element does not match the element given.
sub end {
    my ($self, $name) = @_;
    my $e = $self->current;
    if (defined $name) {
        my $real = $e->name;
        if ($name ne $real) {
            croak ("name mismatch in end: expecting $name, saw $real");
        }
    }
    pop @{ $self->{stack} };
    return $self;
}

# Add an element with possible attributes and content and then immediately end
# it.  This is a shortcut for a start() and end() sequence when no nested
# elements are present.
sub add {
    my ($self, $name, $attrs, $text) = @_;
    return $self->start ($name, $attrs, $text)->end;
}

# Return the root element of a document.
sub root {
    my ($self) = @_;
    return $self->{root};
}

1;

__END__

=for stopwords
WebKDC WebAuth ATTRS Allbery

=head1 NAME

WebKDC::XmlDoc - Manipulate a document of WebKDC::XmlElement objects

=head1 SYNOPSIS

    use WebKDC::XmlDoc;

    my $doc = WebKDC::XmlDoc->new;
    $doc->start ('root');
    $doc->start ('child', { key => 'value' }, 'some content');
    $doc->add ('subchild, 'more content');
    print $doc->current->name, "\n";
    $doc->end;
    $doc->end;
    print $doc->root->name, "\n";

=head1 DESCRIPTION

A WebKDC::XmlDoc represents an XML document as a tree of
WebKDC::XmlElement objects.  It is used internally by the WebKDC module to
create and parse XML documents when talking to a WebAuth WebKDC.

A (non-empty) document has a root element and a stack of open elements.
It is assembled by starting an element (with start(), possibly including
attributes and content), manipulating that element if necessary, and then
ending the element, done recursively.  Once an element has been ended,
there is no way using this interface to further change it, although it can
be retrieved by getting the root of the tree with root() and then walking
the tree.  add() is an optimization that combines start() and end() and is
more efficient if an element has no child elements.

Most manipulation of this document is done via the WebKDC::XmlElement
methods, which allow parsing an XML document into this format, finding
children of a particular element, and converting a document to its XML
representation.  This module only defines the top-level structure and the
methods that have to be called on the document as a whole rather than on
an individual element.

=head1 CLASS METHODS

=over 4

=item new ()

Create a new, empty document.  This document will have no root.  The first
element added with start() or add() will become the root of the document.

=back

=head1 INSTANCE METHODS

=over 4

=item add (NAME[, ATTRS[, CONTENT]])

Add a new element with name NAME as a child of the current element and
immediately close it, equivalent to start() followed immediately by end().
Optional attributes (which should be an anonymous hash of names and
values) and content (which should be a string) may be provided.  To
provide CONTENT without ATTRS, pass C<{}> as ATTRS.  Returns the
WebKDC::XmlDoc object.

If the document is empty, the new element becomes the root.

=item current ()

Returns the current element as a WebKDC::XmlElement object.  The current
element is the most recent element opened by start() and not yet closed
with end().

=item end ([NAME])

End the current element.  If the optional NAME parameter is given, throw
an exception and take no action if the current open element is not named
NAME.  Returns the WebKDC::XmlDoc object.

=item root ()

Returns the root WebKDC::XmlElement object of the document or undef if
the document is empty.  To convert the entire document to XML, use:

    my $xml = $doc->root->to_string;

(which uses the to_string() method of WebKDC::XmlElement).

=item start (NAME[, ATTRS[, CONTENT]])

Add a new element with name NAME as a child of the current element and
make the new element the current element (so subsequent elements added by
start() or add() will be children of it) until the next end().  Optional
attributes (which should be an anonymous hash of names and values) and
content (which should be a string) may be provided.  To provide CONTENT
without ATTRS, pass C<{}> as ATTRS.  Returns the WebKDC::XmlDoc object.

If the document is empty, the new element becomes the root.

=back

=head1 AUTHOR

Roland Schemers and Russ Allbery <rra@stanford.edu>

=head1 SEE ALSO

WebKDC(3), WebKDC::XmlElement(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
