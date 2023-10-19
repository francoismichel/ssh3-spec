---
title: "Running SSH over HTTP/3 connections"
abbrev: "SSH3"
category: info

docname: draft-michel-ssh3-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "francoismichel/ssh3-spec"
  latest: "https://francoismichel.github.io/ssh3-spec/draft-michel-ssh3.html"

author:
 -
    fullname: "François Michel"
    organization: UCLouvain
    email: "francois.michel@uclouvain.be"

normative:
  QUICv1: RFC9000
  QUIC-RECOVERY: RFC9002
  SSH-TRANSPORT: RFC4253
  SSH-CONNECT: RFC4254

informative:


--- abstract

The SSH protocol offers a series of secure services atop an unsecure network.
SSH traditionnally runs atop the TCP transport protocol. This document
defines mechanisms to run the SSH protocol and provide the same set of
services atop HTTP/3.


--- middle

# Introduction

This document defines mechanism to run the SSH protocol over HTTP/3 connections.
Currently, it is still unclear whether HTTP/3 or WebTransport should be used
as the transport layer for SSH/3. We currently only consider HTTP/3 as
WebTransport is not standardized yet.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# SSH session
An SSH session can be started using the HTTP/3 CONNECT method.
The stream ID used for this request is then remembered by each endpoint
as the SSH session ID, uniquely identifying this SSH session.


# Channels

Similarly to {{SSH-TRANSPORT}}, SSH/3 defines bidirectional channels over
which the endpoints exchange messages. Each channel runs over a bidirectional
HTTP/3 stream and is attached to a single SSH session.

## Opening a channel

Similarly to what is done for WebTransport, SSH channels can be
opened over HTTP/3 bidirectional streams using a specific signal value.
For experimental purpose this value is chosen at random and will change over
time.

```
Channel {
    Signal Value (i) = 0xaf3627e6,
    Session ID (i),
    Channel Type Length (i)
    Channel Type (..)
    Maximum Packet Size (i)
    SSH messages (..)
}
```

TODO: do we want to use an "authentication token" to avoid hijacking
an SSH session ? WebTransport does not define that, so it may be OK
to ask the SSH implementation to ensure a client cannot choose the
session ID.
 
The Channel Type is a UTF-8-encoded string whose length is defined
by the Channel Type Length field.
The Maximum Packet Size field defines the maximum size in bytes of
SSH packets.

## Channel types

This document defines three following channel types, the two first being
also defined in {{SSH-CONNECT}}:

- session
- x11

Compared to SSHv2, direct-tcpip and forwarded-tcpip channel types are not
defined as the MASQUE proxy will be used instead.

## Messages

Messages are exchanged over channels similarly to SSHv2. The same messages
format apply.

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
