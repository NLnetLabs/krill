Event Sourcing Overview
=======================

The Audit is the Truth
----------------------

Event Sourcing is a technique based on the concept that the current state of a thing is
based on a full record of past events - which can be replayed - rather than saving / loading
the state using something like object-relational-mapping or serialization.

A commonly used example to explain this concept is bookkeeping. In bookkeeping one tracks
all financial transactions, like money coming in and going out of an account. The current
state of an account is determined by the culmination of all these changes over time. Using
this approach, and assuming that no one altered the historical records, we can be 100% certain
that the current state reflects reality. Conveniently, we also have a full audit trail which
can be shown.


CQRS and Domain Driven Design
-----------------------------

Event Sourcing is often combined with CQRS: Command Query Responsibility Segregation. The
idea here is that there is a separation between intended changes (commands) sent to your
entity, the internal state of the entity, and its external representation.

Separating these concerns we can also borrow heavily from ["Domain Driven Design"](https://en.wikipedia.org/wiki/Domain-driven_design).
In DDD structures are organized into so-called of "aggregates" of related structures. At
their root they are joined by an "aggregate root".

Commands, Events and Data
-------------------------

This separation means that the aggregate is a bit like a black box to the outside world,
but in a positive sense. Users of the code just need to know what messages of intent (commands)
they can send to the it. This interface, like an API, should be fairly stable.

The first thing to do when a command is sent is that an aggregate is retrieved from storage,
so that it can receive a command. The state of the aggregate is the result of all past
events - but, because this can get slow, aggregate snapshots are often used for efficiency.
If a snapshot does not include the latest events, then they are simply re-applied to it.

When an aggregate receives a command it can see if a change can be applied. It is fully
in charge of its own consistency. If it isn't then the aggregate root is usually at the
wrong level. The result of command can either be an error - the command is rejected - or
a number of events which represent state changes are applied to the aggregate.

When events are applied they are also saved, so that they can be replayed later. Furthermore,
implementations often use message queues where events are posted as well. This allows other
components in the code to be triggered by changes in an aggregate.

In its purest form (hint: we don't do this), these messages can then be used to (re-)generate
one or more data representations that users can *query*. E.g. you could populate data tables
in a SQL database if that floats your boat.

More.. Libraries?
-----------------

This combination of techniques has been championed by various people, most notably Greg Young
and Martin Fowler. You can do your own internet search find out much more about how this can
work, and how it is done in other projects.

If you search for it you will find that there are many blog posts about how people made this
work for their project. There are also many libraries, for many languages, that provide ES-CQRS
frameworks. Some of these libraries will have you believe that their implementation is the
**right** way of doing this... but we believe that there is more than one way to happiness. So,
in Krill we have chosen to use our own local implementation. This lets us use the concepts,
but it allows us the flexibility to adapt it to our specific needs, and avoids the complication
from concepts that we do not need.