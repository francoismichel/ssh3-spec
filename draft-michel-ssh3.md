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
 -
    fullname: "Olivier Bonaventure"
    organization: UCLouvain
    email: "olivier.bonaventure@uclouvain.be"

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
  EXTENDED-CONNECT: RFC8441
  HTTP-DATAGRAM: RFC9297
  WEBTRANSPORT-H3: I-D.ietf-webtrans-http3
  HTTP-SIGNATURE: I-D.ietf-httpbis-unprompted-auth
  URI: RFC3986

informative:


--- abstract

The SSH protocol offers a series of secure services on a remote computer across an insecure network.
SSH traditionally runs over the TCP transport protocol. This document defines mechanisms
to run the SSH protocol and provide a comparable set of services using HTTP/3.
Running SSH over HTTP/3 allows several benefits such as the scalability offered by HTTP
multiplexing, relying on TLS for secure channel establishment and the use of X.509 certificates and HTTP Authentication schemes for client and server authentication.



--- middle

# Introduction

This document defines mechanisms to run the SSH Connection protocol
{{SSH-CONNECT}} over HTTP/3 connections. The mechanisms used for
establishing an SSH3 conversation are similar to the
WebTransport session establishment {{WEBTRANSPORT-H3}}. WebTransport is also a good transport layer candidate for SSH3. The current
SSH3 prototype is built directly over HTTP/3 since there is no public
WebTransport implementation meeting all our requirements as of now.
The semantics of HTTP/2 being comparable to HTTP/3, the mechanisms
defined in this document may be implemented using HTTP/2. This document
is a first introductory document and we limit its current scope to HTTP/3.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Estalishing an SSH3 conversation {#establishing}
We choose the name conversation to avoid ambiguities with the existing
concepts of SSH shell session and QUIC connection.
An SSH3 conversation can be started using the HTTP/3 Extended CONNECT
method {{EXTENDED-CONNECT}}. The `:protocol` pseudo-header MUST be set
to `ssh3` and the `:scheme` pseudo-header MUST be set to `https`.
If an SSH3 client or server supports the UDP forwarding feature, it MUST indicate support for HTTP/3 datagrams by sending a SETTINGS_H3_DATAGRAM value set to 1 in their
SETTINGS frame (see [Section 2.1.1]() of [HTTP-DATAGRAM]).

An SSH3 server listens for CONNECT requests with the `ssh3` protocol
on URI templates having the `username` variable. Example URIs can be found below.

~~~~
https://example.org:4443/ssh3?user={username}
https://proxy.example.org:4443/ssh3{?username}
~~~~

\[\[Note: In the current prototype, percent-encoding is used for characters outside the allowed set of {{URI}}. An alternative can be to perform base64url encoding of the username instead.]]

Authentication material is placed inside the `Authorization` header of the Extended CONNECT request. If an SSH3 endpoint is available to the HTTP/3 server and if the user is successfully authenticated and authorized, the server responds with a 2xx HTTP status code and the conversation is established.

The stream ID used for the Extended CONNECT request is then remembered by each endpoint as the SSH conversation ID, uniquely identifying this SSH conversation.

## Authenticating the client

Authorization of the CONNECT request is done using HTTP Authorization
as defined in {{HTTP-SEMANTICS}}, with no restriction on the authentication scheme used. If no authentication scheme is provided or if the authentication
scheme is not supported by the server, the server SHOULD respond with a
401 (Unauthorized) response message. Once the user authentication is successful, the SSH3 server can process the request and start the conversation. This section only provides example user authorization
mechanisms. Other mechanisms may be proposed in the future in separate
documents. The two first examples are implemented by our current
prototype. The third example leverages the Signature authentication
scheme {{HTTP-SIGNATURE}} and will be preferred for public key
authentication in future versions of our prototype.

### Example: password authentication using HTTP Basic Authentication

Password-based authentication is performed using the HTTP
Basic authentication scheme {{HTTP-BASIC}}. The user-id part of the
`<credentials>` in the Authorization header MUST be equivalent to
the `username` variable in the request URI defined in {{establishing}}.

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

### Example: public key authentication using HTTP Signature authentication

Public key authentication can also be performed using the HTTP Signature
Authentication scheme {{HTTP-SIGNATURE}}. The `<k>` parameter designates
the key ID of the public key used the the authentication process.
Classical SSH implementations usually do not assign IDs to public keys.
The value of `<k>` can therefore be set to the cryptographic hash of
the public key instead.

~~~~
  Client
     |                QUIC HANDSHAKE                 |
     |<--------------------------------------------->|
     |                                               |
     | HTTP/3, Stream x CONNECT /<path>?user=<user>  |
     |    :protocol="ssh3"                           |
     |    Signature k=<k>, a=<a>,s=<s>,v=<v>,p=<p>   |
     |---------------------------------------------->|
     |                                               |
     |               HTTP/3, Stream x 200 OK         |
     |<----------------------------------------------|
     |                                               |
     |           Conversation established            |
     +-----------------------------------------------+
     |                                               |
~~~~

# SSH Connection protocol

This document reuses the SSH connection protocol defined in {{SSH-CONNECT}}. SSH Channels are run over their dedicated HTTP streams and carry SSH messages. The `boolean` and `string` data types defined in {{SSH-ARCH}} are reused. The `byte`, `uint32` and `uint64` data types are replaced by variable-length integers as defined in [Section 16](https://datatracker.ietf.org/doc/html/rfc9000#name-variable-length-integer-enc) of {{QUIC}}.

## Channels

Similarly to {{SSH-TRANSPORT}}, SSH3 defines bidirectional channels over
which the endpoints exchange SSH messages. Each channel runs over a bidirectional
HTTP/3 stream and is attached to a single SSH conversation. In this document,
channels are therefore not assigned a channel number conversely to SSHv2.


### Opening a channel

SSH channels can be opened on HTTP/3 client-initiated bidirectional streams using a specific signal value. By default, HTTP/3 considers every client-initiated bidirectional stream as a request stream. Similarly to WebTransport, SSH3 extends HTTP/3 using a specific signal value. Upon receiving HTTP/3 settings announcing SSH3 server support, a client can open a stream with this signal value to indicate that it is not a request stream and that the remaining stream bytes will be used arbitrarily by the SSH3 protocol to carry the content of a channel.
For experimental purpose, the signal value is chosen at random and will change over time. The content of an HTTP/3 stream carrying an SSH3 channel is illustrated below.

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

The first byte send on the HTTP/3 stream is the Signal Value. The
Channel Type is a UTF-8-encoded string whose length is defined
by the Channel Type Length field.

\[\[Note: SSHv2 uses text-based channel IDs. Should we keep that or
use somthing else instead ? If we change, we loose a 1-1 mapping with SSHv2.]]

The Maximum Message Size field defines the maximum size in bytes of
SSH messages.

The remaining bytes of the stream are interpreted as a sequence of SSH messages. Their format and length can vary depending on the message type (see {{messages}}).

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

### Messages {#messages}

Messages are exchanged over channels similarly to SSHv2. The same messages
format as the one defined in {{SSH-CONNECT}} applies, with channel numbers removed from the messages headers as channel run over dedicated HTTP streams. Hereunder is an example showing the wire format of the `exit-status` SSH message for SSH3. Its SSHv2 variant is described in [Section 6.10](https://datatracker.ietf.org/doc/html/rfc4254#section-6.10) of {{SSH-CONNECT}}.

~~~~
ExitStatusMessage {
    Message Type (string) = "exit-status",
    Want Reply (bool) = false,
    Exit Status (i)
}
~~~~

# Version Negotiation

For SSH3 implementations to be able to follow the versions of this draft
while being interoperable with a large amount of peers, we define the
"`ssh-version`" header to list the supported draft versions. The value
of this field sent by the client is a comma-separated list of strings
representing the filenames of the supported drafts without the "`draft-`"
prefix.
For instance, SSH3 clients implementing this draft in versions 00 and 01
send the "`ssh-version: michel-dispatch-ssh3-00,michel-dispatch-ssh3-01`"
HTTP header in the CONNECT request.
Upon receiving this header, the server chooses a version from the ones
supported by the client. It then sets this single version as the value
of the "`ssh-version`" header.

# Security Considerations

Running an SSH3 endpoint with weak or no authentication methods exposes
the host to non-negligible risks allowing attackers to gain full control
of the server. SSH3 servers should not be run without authentication
and user authentication material should be verified thoroughly. Public
key authentication should be preferred to passwords.

It is strongly recommended to deploy public TLS certificates on SSH3
servers. Using valid TLS certificates on the server allows their
automatic verification with no explicit user action required.
Connecting an SSH3 client to a server with no valid cerificate exposes
the user to the same risk incurred by SSHv2 endpoints relying on Host
keys: the user needs to manually validate the certificate before
connecting to avoid an attacker to impersonate the server and
access the keystrokes typed by the user during the conversation.


# IANA Considerations

## HTTP Upgrade Token
This document will request IANA to register "ssh3" in the "HTTP Upgrade
Tokens" registry maintained at <https://www.iana.org/assignments/http-upgrade-tokens>.

\[\[Note: This may be removed if we decide to run SSH3 atop WebTransport instead of
HTTP/3 only.]]


--- back

# Acknowledgments
{:numbered="false"}

We warmly thank Lucas Pardue and David Schinazi for their precious
comments on the document before the submission.
