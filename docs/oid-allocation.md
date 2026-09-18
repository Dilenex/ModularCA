# Object identifier allocation

Dilenex LLC holds Private Enterprise Number **66874**, registered with IANA. Every object
identifier this organisation mints lives under:

```
1.3.6.1.4.1.66874
```

This file is the registry. An arc that is not written down here is unallocated. Record an
allocation before using it, not after, because an object identifier that has reached a client's
certificate cannot be taken back.

## Allocated

| Arc | What it identifies |
|---|---|
| `1.3.6.1.4.1.66874` | Dilenex LLC: the enterprise arc itself |
| `1.3.6.1.4.1.66874.1` | ModularCA, the product |
| `1.3.6.1.4.1.66874.1.1` | generated certificate template identifiers, for Windows autoenrollment |

## Reserved, not yet used

| Arc | Intended for |
|---|---|
| `1.3.6.1.4.1.66874.1.2` | certificate policy identifiers, when a CA asserts a policy of its own |
| `1.3.6.1.4.1.66874.1.3` | private certificate extensions, if the product ever defines one |
| `1.3.6.1.4.1.66874.1.4` | private extended key usages |
| `1.3.6.1.4.1.66874.2` and above | a second Dilenex product, should there be one |

## How long a base arc may be

A generated template identifier appends four arcs of up to ten digits to its base arc, which costs
forty-four characters. The column that stores it holds a hundred and twenty-eight, so a base arc
may be eighty-four characters. That is room for an enterprise number of any length IANA issues,
with two or three levels beneath it.

It was not always. The column held sixty-four until 2026-09-17, leaving twenty characters, which
is too few for `1.3.6.1.4.1.66874.1.1` at twenty-one and too few for any seven or eight digit
enterprise number with a sub-arc. An operator configuring their own arc would have been refused.
The column was widened rather than the allocation flattened, because the limit was the real defect
and it belonged to every customer, not only to us.

## Certificate template identifiers

Set `Msae:TemplateOidArc` to `1.3.6.1.4.1.66874.1.1`. A generated template identifier is that arc
followed by four arcs of at most thirty-one bits each, derived from the template's own identifier.

The four-arc shape exists because Windows parses each arc of an object identifier into a signed
sixty-four bit integer and silently drops a template whose identifier does not fit. The earlier
generated form put a whole template identifier into one arc, which overflowed for about half of
all templates, and the symptom was a template that simply never appeared on a client with no error
anywhere.

Templates whose identifier an operator typed are never rewritten, including ones that sit under
the arc of an Active Directory Certificate Services deployment being migrated from. Only generated
identifiers move.

## What happens when the arc is first configured

`MsaeTemplateOidRepair` runs at startup. While no arc is configured it only counts the templates
waiting. Once the arc is set it moves every generated identifier under it in one pass, both the
pre-2026-09-15 single-arc form and the four-arc form under the placeholder arc, recognising them
by recomputing each from the template's own identifier.

This is a client-visible, one-time event, and it should happen once, deliberately. A Windows client
matches a certificate it holds to a template by the identifier in the certificate's template
extension, so after the move every enrolled machine sees its template as new and enrolls again at
its next autoenrollment pulse. Certificates already issued keep the old identifier and stay valid
until they expire. Plan it like any other change that causes a fleet to re-enroll: outside a
maintenance window it will look like a storm.

## Before the number arrived

Generated identifiers were placed under `2.25`, which is the arc for identifiers derived from a
universally unique identifier and is legitimate but anonymous. Anything still there is what the
repair moves.
