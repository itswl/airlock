"""What sits around the core: sources that post signals in, subscribers that carry notifications out.

The core is one line — a signal comes in, one investigator looks, a plan is
written, you approve it once, the launcher runs it in containers, and all of it
is recorded. Nothing here is on that line. A watcher that reads chat is a
source: it posts signed signals to an intake door like any monitoring system
would. A chat adapter is a subscriber: it receives the outlet's signed
notifications and speaks back through the adapter protocol. The self-check is
a script that reads health endpoints.

So every module here uses only what the core publishes: its intake doors, its
outlet, its adapter endpoints, its health endpoints. The core never imports
anything from here (tests/test_extras.py checks that). Any of these can be
replaced by something else that speaks the same protocols, and none of them
needs to change when the core does.
"""
