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
  SSH-ARCH: RFC4251
  SSH-TRANSPORT: RFC4253
  SSH-CONNECT: RFC4254
  HTTP-SEMANTICS: RFC9110
  OAUTH2: RFC6749
  HTTP-BASIC: RFC7617
  JWT: RFC7519
  QUIC: RFC9000
  OAUTH2-JWT: RFC9068

informative:


--- abstract

The SSH protocol offers a series of secure services atop an unsecure network.
SSH traditionnally runs atop the TCP transport protocol. This document
defines mechanisms to run the SSH protocol and provide the same set of
services atop HTTP/3.


--- middle

# Introduction

This document defines mechanism to run the SSH Connection protocol {{SSH-CONNECT}} over HTTP/3 connections.
Currently, it is still undecided whether HTTP/3 or WebTransport should be used as the transport layer for SSH3. We currently only consider HTTP/3 as WebTransport is not standardized yet.
The semantics of HTTP/2 being comparable with HTTP/3, the mechanisms
defined in this document may be implemented using HTTP/2. This document being a first introductory document, we limit its current scope to HTTP/3.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# SSH conversation
An SSH conversation can be started using the HTTP/3 CONNECT method.
The stream ID used for this request is then remembered by each endpoint
as the SSH conversation ID, uniquely identifying this SSH conversation.
We choose the name conversation to avoid ambiguities with the existing
concepts of SSH shell session and QUIC connection.

An SSH3 server listens for CONNECT requests with the `ssh3` protocol
at a URI templates having the `username` variable. Example URIs can be found below.

~~~~
https://example.org/ssh3/{username}
https://proxy.example.org:4443/ssh3?u={username}
https://proxy.example.org:4443/ssh3{?username}
~~~~

## Authenticating the client

Authorization of the CONNECT request is done using HTTP Authorization
as defined in {{HTTP-SEMANTICS}}, with no restriction on the authentication scheme used. If no authentication scheme is provided or if the authentication
scheme is not supported by the server, the server SHOULD respond with a
401 (Unauthorized) response message. Once the user authentication is successful, the SSH3 server can process the request and start the conversation. This section provides example user authorization
mechanisms. Other mechanisms may be proposed in the future.

### Example: password authentication using HTTP Basic Authentication

Password-based authentication is performed using the HTTP
Basic authentication scheme {{HTTP-BASIC}}.

~~~~
  Client
     |                QUIC HANDSHAKE                 |
     |<--------------------------------------------->|
     |                                               |
     | HTTP/3, Stream x CONNECT /<path>?user=<user>  |
     |         :protocol="ssh3"                      |
     |         Authorization="Basic <credentials>"   |
     |---------------------------------------------->|
     |                                               |
     |               HTTP/3, Stream x 200 OK         |
     |<----------------------------------------------|
     |                                               |
     |           Conversation established            |
     +-----------------------------------------------+
     |                                               |
~~~~


### Example: public key authentication using OAUTH2 and JWTs

Classical public key authentication can be performed using the OAUTH2 framework {{OAUTH2}}:
the HTTP Bearer authentication scheme is used to carry an OAUTH access token encoded in the JWT {{JWT}} format {{OAUTH2-JWT}}.

~~~~
  Client
     |                QUIC HANDSHAKE                 |
     |<--------------------------------------------->|
     |                                               |
     | HTTP/3, Stream x CONNECT /<path>?user=<user>  |
     |         :protocol="ssh3"                      |
     |         Authorization="Bearer <JWT token>"    |
     |---------------------------------------------->|
     |                                               |
     |               HTTP/3, Stream x 200 OK         |
     |<----------------------------------------------|
     |                                               |
     |           Conversation established            |
     +-----------------------------------------------+
     |                                               |
~~~~

For classical client-server public key authentication with no
third-party involved, only the following claims are required (see
{{JWT}} for their definition):

- `sub`: set to `ssh3-<user>`
- `iat`: set to the date of issuance of the JWT
- `exp`: set to a short expiration value to limit the token replay window

The `jti` claim may also be used to prevent the token from
being replayed.

# SSH Connection protocol

This document reuses the SSH connection protocol defined in {{SSH-CONNECT}}. SSH Channels are run over their dedicated HTTP streams and carry SSH messages. The `boolean` and `string` data types defined in {{SSH-ARCH}} are reused. The `byte`, `uint32` and `uint64` data types are replaced by variable-length integers as defined in [Section 16](https://datatracker.ietf.org/doc/html/rfc9000#name-variable-length-integer-enc) of {{QUIC}}.

## Channels

Similarly to {{SSH-TRANSPORT}}, SSH3 defines bidirectional channels over
which the endpoints exchange SSH messages. Each channel runs over a bidirectional
HTTP/3 stream and is attached to a single SSH conversation. In this document,
channels are therefore not assigned a channel number conversely to SSHv2.


### Opening a channel

SSH channels can be
opened over HTTP bidirectional streams using a specific signal value.
For experimental purpose, this value is chosen at random and will change over
time.

~~~~
Channel {
    Signal Value (i) = 0xaf3627e6,
    Conversation ID (i),
    Channel Type Length (i)
    Channel Type (..)
    Maximum Message Size (i)
    SSH messages (..)
}
~~~~

The Channel Type is a UTF-8-encoded string whose length is defined
by the Channel Type Length field.
The Maximum Message Size field defines the maximum size in bytes of
SSH messages.

### Channel types

This document defines the following channel types, the two first being
also defined in {{SSH-CONNECT}}:

- session
- x11
- direct-tcp
- direct-udp
- reverse-tcp
- reverse-udp

The direct-tcp and direct-udp channels request TCP and UDP port
forwarding from a local port on the client towards a remote address accessible from the remote host.
The reverse-tcp and reverse-udp channels are use to request
the forwarding of UDP packets and TCP connections from a specific port on the remote host to the client.

### Messages

Messages are exchanged over channels similarly to SSHv2. The same messages
format as the one defined {{SSH-CONNECT}} applies, with channel numbers removed from the messages headers as channel run over dedicated HTTP streams. Hereunder is an example showing the wire format of the `exit-status` SSH message for SSH3. Its SSHv2 variant is described in [Section 6.10](https://datatracker.ietf.org/doc/html/rfc4254#section-6.10) of {{SSH-CONNECT}}.

~~~~
ExitStatusMessage {
    Message Type (string) = "exit-status",
    Want Reply (bool) = false,
    Exit Status (i)
}
~~~~

# Version Negotiation
TODO

# Security Considerations

TODO


# IANA Considerations

TODO


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
