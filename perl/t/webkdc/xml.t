#!/usr/bin/perl -w
#
# Basic tests for WebKDC::XmlDoc and WebKDC::XmlElement.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use Test::More tests => 56;

BEGIN {
    use_ok ('WebKDC::XmlDoc');
    use_ok ('WebKDC::XmlElement');
}

# Create a basic empty element.
my $e = WebKDC::XmlElement->new;
isa_ok ($e, 'WebKDC::XmlElement');
is ($e->content, undef, '... empty content');
is ($e->content_trimmed, undef, '... also when trimmed');
is (scalar %{ $e->attrs }, 0, '... no attributes');
is (scalar @{ $e->children }, 0, '... no children');
ok (!$e->has_attrs, '... has_attrs returns false');
ok (!$e->has_children, '... has_children returns false');
is ($e->name, undef, '... has no name');
is ($e->find_child ('foo'), undef, '... and no children named foo');

# Set some attributes and contents.
is ($e->name ('foo'), 'foo', 'Setting name');
is ($e->name, 'foo', '... and name is set');
is ($e->content ('  test  '), '  test  ', 'Setting content');
is ($e->content, '  test  ', '... and content is set');
is ($e->content_trimmed, 'test', '... and trimmed content is correct');
$e->append_content ('foo');
is ($e->content, '  test  foo', 'Content correct after append');
is ($e->content_trimmed, 'test  foo', '... and trimmed content is correct');
is ($e->attr ('a1', 'v1'), 'v1', 'Setting attribute a1');
is ($e->attr ('a1'), 'v1', '... and attribute is set');
is ($e->has_attrs, 1, '... and has_attrs is now true');
is ($e->attr ('a2', 'v2'), 'v2', 'Setting attribute a2');
is ($e->attr ('a2'), 'v2', '... and attribute is set');
is_deeply ($e->attrs, { a1 => 'v1', a2 => 'v2' }, '... and attrs is correct');
is_deeply ($e->attrs ({ a3 => 'v3' }), { a3 => 'v3' }, 'Setting all attrs');
is ($e->attr ('a3'), 'v3', '... and a3 is now set');
is ($e->attr ('a1'), undef, '... and a1 is not');

# Serialize to XML.
my $xml = $e->to_string;
is ($xml, '<foo a3="v3">  test  foo</foo>', 'XML serialization correct');
is_deeply (WebKDC::XmlElement->new ($xml), $e,
           '... and a new element from XML matches');

# Add some children.
$e->add_child (WebKDC::XmlElement->new ('<bar />'));
$e->add_child (WebKDC::XmlElement->new ('<bar>content</bar>'));
$e->add_child (WebKDC::XmlElement->new ('<baz>  </baz>'));
is ($e->has_children, 1, 'Children now exist');
my @children = @{ $e->children };
is (scalar (@children), 3, '... three of them');
is ($children[0]->name, 'bar', '... name of first is correct');
is ($children[0]->content, undef, '... with no content');
is ($children[1]->name, 'bar', '... name of second is correct');
is ($children[1]->content, 'content', '... with correct content');
is ($children[2]->name, 'baz', '... name of third is correct');
is ($children[2]->content, '  ', '... with correct content');
is ($children[2]->content_trimmed, '', '... and correct trimmed content');
my $child = $e->find_child ('bar');
is ($child, $children[0], 'find_child returns first match');
$child->append_content ('bleh');
is ($child->content, 'bleh', 'Appending to empty content works');
$child = $e->find_child ('baz');
is ($child, $children[2], 'Finding the third child works');
shift @children;
$e->children (\@children);
is (scalar (@{ $e->children }), 2, 'Replacing the children works');
$child = $e->find_child ('bar');
is ($child->content, 'content', '... and the first bar matches expectations');
is ($child->content (''), '', '... and removing content works');
$e->add_child (WebKDC::XmlElement->new ('<empty/>'));

# Serialize to XML again.
$xml = $e->to_string;
is ($xml, '<foo a3="v3">  test  foo<bar></bar><baz>  </baz><empty /></foo>',
    'XML serialization correct');
$child->content ('b');
$xml = $e->to_string;
is ($xml, '<foo a3="v3">  test  foo<bar>b</bar><baz>  </baz><empty /></foo>',
    'XML serialization correct without empty element');
is_deeply (WebKDC::XmlElement->new ($xml), $e,
           '... and a new element from XML matches');

# Build the same document via WebKDC::XmlDoc.
my $doc = WebKDC::XmlDoc->new;
isa_ok ($doc, 'WebKDC::XmlDoc');
is ($doc->root, undef, 'Empty document has no root');
$doc->start ('foo', { a3 => 'v3' }, '  test  foo');
is ($doc->current->name, 'foo', 'start and current work');
$doc->add ('bar', {}, 'b');
$doc->add ('baz', {}, '  ');
$doc->add ('empty');
$doc->end;
my $current = eval { $doc->current };
is ($current, undef, 'No current after end');
like ($@, qr/^not in an element/, '... with correct exception');
is_deeply ($doc->root, $e, 'Resulting document matches');
$xml = $doc->root->to_string;
is ($xml, '<foo a3="v3">  test  foo<bar>b</bar><baz>  </baz><empty /></foo>',
    'Resulting XML serialization matches');

# Test closing a specific element.
$doc = WebKDC::XmlDoc->new;
$doc->start ('foo', { }, '  test foo');
$doc->start ('bar', { }, '  test bar');
$doc->end ('bar');
is ($doc->current->name, 'foo', 'Closing a tag by name works');
eval { $doc->end ('baz') };
like ($@, qr{^name mismatch in end: expecting baz, saw foo}ms,
      '... and giving a wrong tag name croaks');
