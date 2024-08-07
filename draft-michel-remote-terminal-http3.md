---
title: "Remote terminal over HTTP/3 connections"
abbrev: "RTH3"
category: exp

docname: draft-michel-remote-terminal-http3-latest
submissiontype: independent
number:
date:
consensus: false
v: 3
area: sec
workgroup: Security Dispatch
keyword:
  - ssh
  - http
  - h3
  - quic
  - tls
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "francoismichel/ssh3-spec"
  latest: "https://francoismichel.github.io/ssh3-spec/draft-michel-remote-terminal-http3.html"

author:
 -
    fullname: "François Michel"
    organization: UCLouvain
    email: "francois.michel@uclouvain.be"
 -
    fullname: "Olivier Bonaventure"
    organization: UCLouvain and WELRI
    email: "olivier.bonaventure@uclouvain.be"

normative:
  HTTP2: RFC9113
  HTTP3: RFC9114
  SSH-ARCH: RFC4251
  SSH-AUTH: rfc4252
  SSH-TRANSPORT: RFC4253
  SSH-CONNECT: RFC4254
  HTTP-SEMANTICS: RFC9110
  HTTP-BASIC: RFC7617
  JWT: RFC7519
  QUIC: RFC9000
  QUIC-TLS: RFC9001
  QUIC-RECOVERY: RFC9002
  OAUTH2-JWT: RFC9068
  EXTENDED-CONNECT: RFC8441
  HTTP-DATAGRAM: RFC9297
  WEBTRANSPORT-H3: I-D.ietf-webtrans-http3
  HTTP-CONCEALED: I-D.ietf-httpbis-unprompted-auth
  URI: RFC3986
  DOQ: RFC9250
  TCP: RFC9293
  UDP: RFC768

informative:
  OAUTH2: RFC6749
  MOQT: I-D.ietf-moq-transport
  MASQUE: I-D.schinazi-masque-proxy-01
  OPENSSH-5.4:
      title: OpenSSH release 5.4
      author:
      - org:
      date: false
      seriesinfo:
        Web: https://www.openssh.com/txt/release-5.4
  QUIC-ON-STREAMS: I-D.kazuho-quic-quic-on-streams
  PUTTY-CERTIFICATES:
      title: PuTTY Certificates
      author:
      - org:
      date: false
      seriesinfo:
        Web: https://www.chiark.greenend.org.uk/~sgtatham/quasiblog/putty-certificates/
  TECTIA-CERTIFICATES:
      title: Tectia Certificates
      author:
      - org:
      date: false
      seriesinfo:
        Web: https://privx.docs.ssh.com/docs/enabling-certificate-based-authentication-for-ssh-connections
  RFC5961: RFC5961
  ACME: RFC8555
  TERRAPIN:
      title: "Terrapin Attack: Breaking SSH Channel Integrity By Sequence Number Manipulation"
      author: Fabian Bäumer, Marcus Brinkmann, Jörg Schwenk
      seriesinfo:
        DOI: 10.48550/arXiv.2312.12422
      date: 2023
      author:
        -
          ins: F. Bäumer
          name: Fabian Bäumer
        -
          ins: M. Brinkmann
          name: Marcus Brinkmann
        -
          ins: J. Schwenk
          name: Jörg Schwenk
  RFC8308: RFC8308
  OpenID.Core:
      title: "OpenID Connect Core 1.0"
      author:
        -
          ins: N. Sakimura
          name: N. Sakimura
        -
          ins: J. Bradley
          name: J. Bradley
        -
          ins: M. Jones
          name: M. Jones
        -
          ins: B. de Medeiros
          name: B. de Medeiros
        -
          ins: C. Mortimore
          name: C. Mortimore
      seriesinfo:
        Web: http://openid.net/specs/openid-connect-core-1_0.html
  OASIS.saml-core-2.0-os:
      title: "Assertions and Protocols for the OASIS Security Assertion Markup Language (SAML) V2.0"
      author:
        - ins: S. Cantor
          name: S. Cantor.
        - ins: J. Kemp
          name: J. Kemp
        - ins: R. Philpott
          name: R. Philpott
        - ins: E. Maler
          name: E. Maler
      seriesinfo:
        Web: http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
  WebAuthn:
      title: "Web Authentication: An API for accessing Public Key Credentials Level 3"
      author:
      seriesinfo:
        Web: https://www.w3.org/TR/webauthn-3/
  PROTOTYPE:
      title: "SSH3: faster and rich secure shell using HTTP/3"
      author:
        - ins: F. Michel
          name: François Michel
      seriesinfo:
        Web: https://github.com/francoismichel/ssh3


--- abstract

The secure shell (SSH) traditionally offers its secure services over an insecure network using the TCP transport protocol. This document defines mechanisms to access remote terminals by running the SSH Connection protocol over HTTP/3 using Extended CONNECT.
Remote terminals over HTTP/3 enables additional benefits such as the scalability offered by HTTP
multiplexing, relying on TLS for secure channel establishment leveraging X.509 certificates, HTTP Authentication schemes for client and server authentication, UDP port forwarding
and stronger resilience against packet injection attacks and middlebox interference.



--- middle


# Introduction

The SSH protocol {{SSH-ARCH}} provides a secure way to access computers remotely over an untrusted network. SSH is currently the most popular way to access Unix hosts and network equipments remotely. Built atop the unencrypted TCP protocol  {{TCP}}, SSH proposes its own mechanisms to establish a secure channel {{SSH-TRANSPORT}} and perform user authentication {{SSH-AUTH}}. Once the secure session is established and the user is authenticated and authorized, SSH uses the Connection protocol to run and manage
remote processes and functionalities executed on the remote host {{SSH-CONNECT}}.
Among others, SSH provides different services such as remote program execution, shell access, and TCP port forwarding.
{{ssh2-architecture}} provides a graphical representation of the SSHv2 protocol stack.

~~~~

     +------------------------------------------------------------+
     |                           SSHv2                            |
     | +---------------+   +---------------+   +----------------+ |
     | | SSH Transport |   |   SSH Auth.   |   | SSH Connection | |
     | |   (RFC4253)   |   |   (RFC4252)   |   |   (RFC4254)    | |
     | +---------------+   +---------------+   +----------------+ |
     |  secure channel            user            SSH services    |
     |   establishment       authentication                       |
     +------------------------------------------------------------+
                                   |
                                   |  - reliable transport
                                   v
               +----------------------------------------+
               |                  TCP                   |
               +----------------------------------------+
~~~~
{: #ssh2-architecture title="The SSHv2 architecture protocol stack."}

This document defines mechanisms to run the SSH Connection protocol
{{SSH-CONNECT}} over HTTP/3. The secure channel establishment uses TLS included in QUIC {{QUIC}} {{QUIC-TLS}} while user authentication
is performed using existing HTTP authentication schemes.
{{architecture-goal}} provides a graphical representation of the architecture proposed in this document.
One benefit of the approach is that the HTTP3 and QUIC layers can
evolve independently of this architecture. For instance, new encryption and MAC algorithms
can be added to TLS and used in this architecture without impacting the specification or
adding new code points in this specification for these new algorithms.

~~~~

                 +---------------------------------+
                 |     Remote Terminal over H3     |
                 |   +-------------------------+   |
                 |   |     SSH Connection      |   |
                 |   |       (~RFC4254)        |   |
                 |   +-------------------------+   |
                 |            services             |
                 +---------------------------------+
                   | - user authentication   | - reliable transport
                   | - URL multiplexing      | - secure channel
                   v                         |    establishment
             +-----------------------+       | - streams multiplexing
             |        HTTP/3         |       |            & datagrams
             +-----------------------+       v
             +----------------------------------------------+
             |                 QUIC / TLS                   |
             +----------------------------------------------+

~~~~
{: #architecture-goal title="The proposed architecture."}

The mechanisms used for establishing a remote terminal session
are similar to the WebTransport session establishment {{WEBTRANSPORT-H3}}.
WebTransport is also a good transport layer candidate for this protocol. The current
prototype {{PROTOTYPE}} is built directly over HTTP/3 since there is no public
WebTransport implementation meeting all our requirements as of now.
The semantics of HTTP/2 being comparable to HTTP/3, the mechanisms
defined in this document could be implemented using HTTP/2 if a fallback
to TCP is required. There is an ongoing effort to be able to run HTTP/3 over QUIC on TCP Streams
{{QUIC-ON-STREAMS}}. This document
is a first introductory document. We limit its current scope to HTTP/3
using the classical QUIC.


## How remote terminals benefits from HTTP/3

Using HTTP/3 and QUIC brings several different benefits that are
highlighted in this section.


### QUIC: datagrams, streams multiplexing and connection migration

Using QUIC, data can be sent through both reliable streams and unreliable datagrams. This makes the protocol
able to support port forwarding for both UDP {{UDP}} and TCP-based protocols. Being based exclusively on TCP, SSHv2 does not offer UDP port forwarding and therefore provides no support to UDP-based protocols such as RTP or QUIC.
This lack of UDP support in SSHv2 may become problematic as the use of QUIC-based applications (HTTP/3, MOQT {{MOQT}}, DOQ {{DOQ}}) grows. Support for UDP port forwarding in this architecture also allows accessing real-time media content such as low-latency live video available on the server.
The stream multiplexing capabilities of QUIC allow reducing the head-of-line blocking that SSHv2 encounters when multiplexing several SSH channels over the same TCP connection.

QUIC also supports connection migration ({{Section 9 of QUIC}}).
Using connection migration, a mobile host roaming between networks can
maintain established connections alive across different networks by migrating them
on their newly acquired IP address. This avoids disrupting the remote terminal session
upon network changes.
Finally, QUIC also offers a significantly reduced connection establishment
time compared to the SSHv2 session establishment.


### Protecting transport-layer control fields

Since QUIC integrates authentication and encryption as part of its transport
features, it makes remote terminals over HTTP/3 robust to transport-layer attacks that were possible
with TCP, such as packet injections or reset attacks {{RFC5961}}. For instance, the
recent Terrapin attack {{TERRAPIN}} manipulates the TCP
sequence number to alter the SSH extension negotiation mechanism {{RFC8308}}
and downgrade the client authentication algorithms. QUIC control information
such as packet numbers and frame formats is
authenticated and encrypted starting from the Handshake encryption level.
Furthermore, QUIC prevents middlebox interference.


### Leveraging the X.509 ecosystem

By using TLS for their secure channel establishment, HTTPS and QUIC leverage the X.509 certificates
ecosystem with low implementation effort. TLS and QUIC libraries already implement support
for generating, parsing and verifying X.509 certificates. Similarly to classical OpenSSH certificates,
this avoids encouraging users to rely on the Trust On First Use pattern when connecting to their
remote hosts. Relying on the X.509 certificates ecosystem additionally enables servers to use
ACME {{ACME}} to automatically (with no additional user action) generate X.509 certificates for their
domain names using well-known certificate authorities such as Let's Encrypt. These certificates are publicly valid and can be verified like classical TLS certificates. Client certificates can also be issued
and used as an authentication method for the client.


### HTTP authentication: compatibility with existing authentication systems

Using HTTP authentication schemes for user authentication allows implementing
diverse authentication
mechanisms such as the classical password-based and public key authentication,
but also popular
web authentication mechanisms such as OpenID Connect {{OpenID.Core}}, SAML2
{{OASIS.saml-core-2.0-os}} or the recent Passkeys/WebAuthn standard
{{WebAuthn}}. All these authentication schemes are already deployed
for managing access to critical resources in different organizations. Sharing
computing resources
using SSHv2 through these mechanisms generally requires the deployment of
a middleware managing the
mapping between identities and SSH keys or certificates. HTTP
authentication allows welcoming these authentication methods directly
and and being interfaced naturally with existing infrastructures. As a
proof-of-concept, OpenID Connect support has been added to our prototype {{PROTOTYPE}}.
Other web authentication standards such as Passkeys/WebAuthn {{WebAuthn}}
allow administrators to restrict remote access to specific client devices in addition to users.

### URL multiplexing and undiscoverability

Relying on HTTP allows easily placing remote terminal endpoints as resources accessible through specific URLs.
First, this makes it easier to integrate remote terminal endpoints on web servers that already perform
user authentication and authorization. Second, it allows placing several remote terminal server instances on the same physical machine on the same port. These instances can run in different virtual machines, containers or
simply different users with user's priviledges and be multiplexed on a URL-basis.
Finally, remote terminal endpoints can be placed behind secret URLs, reducing the exposure of remote terminal hosts to
scanning and brute force attacks. This goes in line with the will of having undiscoverable resources
also tackled by other IETF working groups {{HTTP-CONCEALED}}. This property is not provided by SSHv2 since
the SSHv2 server announces its SSH version string to any connected TCP client. If wanted, remote terminal hosts can be made
indistinguishable from any HTTP server. This is however only complementary to and MUST NOT replace user authentication.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Establishing a remote terminal session {#establishing}

A remote terminal session can be started using the HTTP/3 Extended CONNECT
method {{EXTENDED-CONNECT}}. The `:protocol` pseudo-header MUST be set
to `remote-terminal` and the `:scheme` pseudo-header MUST be set to `https`.
If a remote terminal client or server supports the UDP forwarding feature, it MUST indicate support for HTTP/3 datagrams by sending a SETTINGS_H3_DATAGRAM value set to 1 in their
SETTINGS frame ({{Section 2.1.1 of HTTP-DATAGRAM}}).

A remote terminal server listens for CONNECT requests with the `remote-terminal`
protocol on URI templates having the `username` variable. Example URIs can be
found below.

~~~~
https://example.org:4443/abcd?user={username}
https://proxy.example.org:4443/1234{?username}
~~~~

\[\[Note: In the current prototype {{PROTOTYPE}}, percent-encoding is used for characters outside the allowed set of {{URI}}. An alternative can be to perform base64url encoding of the username instead.]]

{{session-establishment}} illustrates a successful remote terminal session
establishment.

~~~~
       Client
          |                QUIC HANDSHAKE                 |
          |<--------------------------------------------->|
          |                                               |
          | HTTP/3, Stream x CONNECT /<path>?user=<user>  |
          |         :protocol="remote-terminal"                      |
          |         Authorization=<auth_material>         |
          |---------------------------------------------->|
          |                                               |
          |               HTTP/3, Stream x 200 OK         |
          |<----------------------------------------------|
          |                                               |
          |             Session established               |
        --+-----------------------------------------------+--
          |                                               |
          |    (endpoints now run the SSH Connection)     |
          |    (protocol over QUIC streams          )     |
          |                                               |
~~~~
{: #session-establishment title="Successful remote terminal session establishment."}


Authentication material is placed inside the `Authorization` header of the Extended CONNECT request. The format and value of `<auth_material>` depends on the HTTP authentication scheme used ({{authenticating-the-client}} explores several examples of authentication mechanisms). If a
remote terminal endpoint is available to the HTTP/3 server and if the user is successfully authenticated and authorized, the server responds
with a 2xx HTTP status code and the session is established.

The stream ID used for the Extended CONNECT request is then remembered by each endpoint as the remote terminal session ID, uniquely identifying this session.

## Authenticating the client
{: #authenticating-the-client}

Authorization of the CONNECT request is done using HTTP Authorization
as defined in {{HTTP-SEMANTICS}}, with no restriction on the
authentication scheme used. If no Authorization header is present in the
request or if the authentication
scheme is not supported by the server, the server SHOULD respond with a
401 (Unauthorized) response message. Once the user authentication is successful, the remote terminal server can process the request and start the session. This section only provides example user authentication
mechanisms. Other mechanisms may be proposed in the future in separate
documents. The two first examples are implemented by our current
prototype {{PROTOTYPE}}. The third example leverages the Concealed authentication
scheme {{HTTP-CONCEALED}} and will be preferred for public key
authentication in future versions of our prototype.

### Password authentication using HTTP Basic Authentication

Password-based authentication is performed using the HTTP
Basic authentication scheme {{HTTP-BASIC}}. The user-id part of the
`<credentials>` in the Authorization header defined in {{HTTP-BASIC}}
MUST be equal to
the `username` variable in the request URI defined in {{establishing}}.

~~~~
  Client
     |                QUIC HANDSHAKE                 |
     |<--------------------------------------------->|
     |                                               |
     | HTTP/3, Stream x CONNECT /<path>?user=<user>  |
     |         :protocol="remote-terminal"           |
     |         Authorization="Basic <credentials>"   |
     |---------------------------------------------->|
     |                                               |
     |               HTTP/3, Stream x 200 OK         |
     |<----------------------------------------------|
     |                                               |
     |             Session established               |
     +-----------------------------------------------+
     |                                               |
~~~~


### Public key authentication using OAUTH2 and JWTs

Classical public key authentication can be performed using the OAUTH2 framework {{OAUTH2}}:
the HTTP Bearer authentication scheme is used to carry an OAUTH access token encoded in the JWT {{JWT}} format {{OAUTH2-JWT}}.

~~~~
  Client
     |                QUIC HANDSHAKE                 |
     |<--------------------------------------------->|
     |                                               |
     | HTTP/3, Stream x CONNECT /<path>?user=<user>  |
     |         :protocol="remote-terminal"           |
     |         Authorization="Bearer <JWT token>"    |
     |---------------------------------------------->|
     |                                               |
     |               HTTP/3, Stream x 200 OK         |
     |<----------------------------------------------|
     |                                               |
     |             Session established               |
     +-----------------------------------------------+
     |                                               |
~~~~

For classical client-server public key authentication with no
third-party involved, only the following claims are required (see
{{JWT}} for their definition):

- `sub`: set to `remote-terminal-<user>`
- `iat`: set to the date of issuance of the JWT
- `exp`: set to a short expiration value to limit the token replay window

The `jti` claim may also be used to prevent the token from
being replayed.

### Public key authentication using HTTP Concealed authentication

Public key authentication can also be performed using the HTTP Concealed
Authentication scheme {{HTTP-CONCEALED}}. The `<k>` parameter designates
the key ID of the public key used by the authentication process.

~~~~
  Client
     |                QUIC HANDSHAKE                 |
     |<--------------------------------------------->|
     |                                               |
     | HTTP/3, Stream x CONNECT /<path>?user=<user>  |
     |    :protocol="remote-terminal"                |
     |    Concealed k=<k>, a=<a>,s=<s>,v=<v>,p=<p>   |
     |---------------------------------------------->|
     |                                               |
     |               HTTP/3, Stream x 200 OK         |
     |<----------------------------------------------|
     |                                               |
     |             Session established               |
     +-----------------------------------------------+
     |                                               |
~~~~

# Mapping the SSH Connection protocol

This document reuses the SSH Connection protocol defined in {{SSH-CONNECT}}. SSH Channels are run over their dedicated HTTP streams and carry SSH messages. The `boolean` and `string` data types defined in {{SSH-ARCH}} are reused. The `byte`, `uint32` and `uint64` data types are replaced by variable-length integers as defined in {{Section 16 of QUIC}}.

## Channels

Similarly to {{SSH-TRANSPORT}}, this document defines bidirectional channels over
which the endpoints exchange messages. Each channel runs over a bidirectional
HTTP/3 stream and is attached to a single remote terminal session. In this document,
channels are therefore not assigned a channel number conversely to SSHv2.


### Opening a channel

Channels can be opened on HTTP/3 client-initiated bidirectional
streams. By default, HTTP/3 considers every client-initiated
bidirectional stream as a request stream. Similarly to WebTransport,
this protocol extends HTTP/3 using a specific signal value. A remote terminal client can open a stream with
this signal value to indicate that it is not a request stream and that
the remaining stream bytes will be used arbitrarily by the protocol
to carry the content of a channel.
For experimental purpose, the signal value is chosen at random and will
change over time. The current signal value is `0x5e67730e`. The content of an HTTP/3 stream carrying a remote terminal
channel is illustrated below.

~~~~
Channel {
    Signal Value (i) = 0x5e67730e,
    Session ID (i),
    Channel Type Length (i)
    Channel Type (..)
    Maximum Message Size (i)
    SSH messages (..)
}
~~~~

The first value sent on the HTTP/3 stream is the Signal Value. The
Channel Type is a UTF-8-encoded string whose length is defined
by the Channel Type Length field.

\[\[Note: SSHv2 uses text-based channel types. Should we keep that or
use something else instead ? If we change, we loose a 1-1 mapping with SSHv2.]]

The Maximum Message Size field defines the maximum size in bytes of
SSH messages.

The remaining bytes of the stream are interpreted as a sequence of
messages. Their format and length can vary depending on the message type
(see {{messages}}).

### Channel types

This document defines the following channel types, the four first being
also defined in {{SSH-CONNECT}}:

- session
- x11
- direct-tcp
- reverse-tcp
- direct-udp
- reverse-udp

The direct-tcp and direct-udp channels offer TCP and UDP port
forwarding from a local port on the client towards a remote address
accessible from the remote host.
The reverse-tcp and reverse-udp channels offer
the forwarding of UDP packets and TCP connections arriving on a specific port
on the remote host to the client.

### Port forwarding
The HTTP bidirectional stream attached to the `direct-tcp` or `reverse-tcp`
channel directly carries the TCP payload to forward.

For UDP forwarding, UDP packets are carried through HTTP Datagrams
({{Section 2 of HTTP-DATAGRAM}}) whose Quarter Stream IDs refer directly to the
HTTP Stream ID of the corresponding `direct-udp` or `reverse-udp` channel.

Forwarding of other layers (e.g. IP) is left for future
versions of the document.

### Messages {#messages}

Messages are exchanged over channels similarly to SSHv2. The same
message
format as the one defined in {{SSH-CONNECT}} applies, with channel
numbers removed from the messages headers as channel run over dedicated
HTTP streams. Hereunder is an example showing the wire format of the
`exit-status` message. Its SSHv2 variant is described in
{{Section 6.10 of SSH-CONNECT}}.

~~~~
ExitStatusMessage {
    Message Type (string) = "exit-status",
    Want Reply (bool) = false,
    Exit Status (i)
}
~~~~

# Remote terminal and MASQUE

This protocol shares common objectives with the MASQUE proxy {{MASQUE}} and while it
is currently out of scope of this introductory document, interactions between
the two protocols may exist in the future. For instance, a MASQUE endpoint
can be integrated with a remote terminal endpoint to provide diverse forwarding services.
Another possible outcome is the integration of remote terminals in the MASQUE
family of proxies in the form of a "`CONNECT-SHELL`" endpoint.

# Version Negotiation

For remote terminal implementations to be able to follow the versions of this draft
while being interoperable with a large amount of peers, we define the
"`remote-terminal-version`" header to list the supported draft versions. The value
of this field sent by the client is a comma-separated list of strings
representing the filenames of the supported drafts without the "`draft-`"
prefix.
For instance, remote terminal clients implementing this draft in versions 00 and 01
send the "`remote-terminal-version: michel-remote-terminal-http3-00,michel-remote-terminal-http3-01`"
HTTP header in the CONNECT request.
Upon receiving this header, the server chooses a version from the ones
supported by the client. It then sets this single version as the value
of the "`remote-terminal-version`" header.

# Compatibility TCP-only networks

This protocol can also be made available on networks supporting only TCP
using either HTTP/2 {{HTTP2}} or HTTP/3 {{HTTP3}} with QUIC on Streams {{QUIC-ON-STREAMS}}.

# Security Considerations

Running a remote terminal endpoint with weak or no authentication methods exposes
the host to non-negligible risks allowing attackers to gain full control
of the server. Remote terminal servers should not be run without authentication
and user authentication material should be verified thoroughly. Public
key authentication should be preferred to passwords.

It is recommended to deploy public TLS certificates on remote terminal
servers similarly to classical HTTPS servers.
Using valid public TLS certificates on the server allows their
automatic verification on the client with no explicit user action
required. Connecting a remote terminal client to a server with a certificate
that cannot be validated using the client's trusted Certificate Authorities
exposes the user to the same risk incurred by SSHv2
endpoints relying on host keys: the user needs to manually validate the
certificate before connecting. Ignoring this verification may allow an attacker
to impersonate the server and access the keystrokes typed by the user during the
session.


# IANA Considerations

## HTTP Upgrade Token
This document will request IANA to register "remote-terminal" in the "HTTP Upgrade
Tokens" registry maintained at <https://www.iana.org/assignments/http-upgrade-tokens>.

\[\[Note: This may be removed if we decide to run remote terminals atop WebTransport instead of
HTTP/3 only.]]


--- back

# Acknowledgments
{:numbered="false"}

We warmly thank Maxime Piraux, Lucas Pardue and David Schinazi for their precious
comments on the document before the submission. We also thank Ryan Hurst for all the
motivating discussions around the protocol.
