---
title: "Running SSH over HTTP/3 connections"
abbrev: "SSH3"
category: exp

docname: draft-michel-ssh3-latest
submissiontype: independent
number:
date:
consensus: false
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
  - ssh
  - ssh3
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
  SSH-AUTH: rfc4252
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
  MOQT: I-D.ietf-moq-transport
  MASQUE: I-D.schinazi-masque-proxy-01
  URI: RFC3986


informative:
  OPENSSH-5.4:
      title: OpenSSH release 5.4
      author:
      - org:
      date: false
      seriesinfo:
        Web: https://www.openssh.com/txt/release-5.4
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


--- abstract

SSH traditionally offers its secure services over an insecure network using the TCP transport protocol. This document defines mechanisms
to run the SSH protocol and provide a comparable set of services using HTTP/3.
Running SSH over HTTP/3 allows several benefits such as the scalability offered by HTTP
multiplexing, relying on TLS for secure channel establishment and the use of X.509 certificates and HTTP Authentication schemes for client and server authentication.



--- middle


# Introduction

The SSH protocol {{SSH-ARCH}} provides a secure way to access computers remotely over an untrusted network. SSH is currently the most popular way to access Unix-based hosts remotely. Built atop the unencrypted TCP protocol, SSH proposes its own mechanisms to establish a secure channel {{SSH-TRANSPORT}} and perform user authentication {{SSH-AUTH}}. Once the secure session is established
and the user is authenticated and authorized, SSH runs the Connection protocol to run and manage
remote processes and functionnalities executed on the remote host {{SSH-CONNECT}}.
Among others, SSH provides different services such as remote program execution, shell access and TCP port forwarding. This document defines mechanisms to run the SSH Connection protocol
{{SSH-CONNECT}} over HTTP/3 connections and uses the name "SSH3" to refer to
this solution. The secure channel establishment is performed using QUIC TLS while user authentication
is performed using existing HTTP authentication schemes, simplifying significantly the design of the SSH protocol itself. {{ssh3-architecture-goal}} compares the SSHv2
current architecture (top) and the architectural goal of this document (bottom).
One benefit of the approach is that the HTTP and QUIC layers can
evolve independently of SSH. For instance, new encryption and MAC algorithms
can be added to TLS and use in SSH3 without impacting the specification or
adding new codepoints in SSH3 for these new algorithms.

~~~~

     +------------------------------------------------------------+
     |                           SSHv2                            |
     | +---------------+   +---------------+   +----------------+ |
     | | SSH transport |   | SSH user-auth |   | SSH connection | |
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

________________________________________________________________________

            +-----------------------------------------------+
            |                     SSH3                      |
            |          +-------------------------+          |
            |          | SSH connection protocol |          |
            |          |      (~RFC4254)         |          |
            |          +-------------------------+          |
            |                 SSH services                  |
            +-----------------------------------------------+
                |                            |
                | - user authentication      |
                | - URL multiplexing         | - reliable transport
                |                            | - secure channel
                v                            |    establishment
             +-----------------------+       | - streams multiplexing
             |         HTTP/3        |       |            & datagrams
             +-----------------------+       v
             +----------------------------------------------+
             |                 QUIC / TLS                   |
             +----------------------------------------------+

~~~~
{: #ssh3-architecture-goal title="Top: SSHv2 architecture. Bottom: SSH3 proposed architecture."}

The mechanisms used for establishing an SSH3 conversation
are similar to the WebTransport session establishment {{WEBTRANSPORT-H3}}.
WebTransport is also a good transport layer candidate for SSH3. The current
SSH3 prototype is built directly over HTTP/3 since there is no public
WebTransport implementation meeting all our requirements as of now.
The semantics of HTTP/2 being comparable to HTTP/3, the mechanisms
defined in this document may be implemented using HTTP/2. This document
is a first introductory document and we limit its current scope to HTTP/3.


## How SSH benefits from HTTP/3

Using HTTP/3 and QUIC as a substrate for SSH brings several different benefits. This section highlights
these benefits.


### QUIC: datagrams support, streams multiplexing and connection migration

Using QUIC, SSH3 can send data through both reliable streams and unreliable datagrams. This makes SSH3
able to support port forwarding for both TCP and UDP-based protocols. Being based exclusively on TCP, SSHv2 does not offer UDP port forwarding and therefore provides no support to UDP-based protocols such RTP or the QUIC protocol.
This lack of UDP support in SSHv2 may become problematic as the use of QUIC applications (HTTP/3, MOQT {{MOQT}}) grows in the Internet. Support for UDP port forwarding with SSH3 also allows accessing real-time media content such as low-latency live video available on the server.
The stream multiplexing capabilities of QUIC allow reducing the head-of-line blocking SSHv2 encounters when multiplexing several SSH channels over the same TCP connection.

QUIC also defines the concept of connection migration ({{Section 9 of QUIC}}).
Using connection migrations, mobile hosts roaming between networks can
maintain the connection alive across these networks by migrating the connection
on their newly acquired IP address. This avoids disrupting the SSH conversation
upon network changes.
Finally, QUIC also offers a significantly reduced connection establishment
time compared to the SSHv2 session establishment.


### Protecting transport-layer control fields

Since QUIC integrates authentication and encryption as part of its transport features, it makes
SSH3 robust to transport-layer attacks that were possible with TCP, such as spoofing or reset
attacks {{RFC5961}}. For instance, the recent Terrapin attack {{TERRAPIN}} manipulates the TCP
sequence number to alter the SSH extension negotiation mechanism {{RFC8308}} and downgrade the client
authentication algorithms. QUIC control informations such as packet numbers and frame formats are
authenticated and encrypted starting from the Handshake encryption level.


### Accessing the X.509 ecosystem

Using TLS for its secure channel establishment, HTTPS and QUIC offer access to the X.509 certificates
ecosystem with low implementation effort. TLS and QUIC libraries already implement support
for generating, parsing and verifying X.509 certificates. Similarly to classical OpenSSH certificates,
this avoids SSH users to rely on the Trust On First Use pattern when connecting to their
remote hosts. Relying on the X.509 certificates ecosystem additionally enables SSH3 servers to use
ACME {{ACME}} and automatically (with no additional user action) generate X.509 certificates for their
domain names using well-known certificate authorities such as Let's Encrypt. These certificates are publicly valid and can be verified like classical HTTPS certificates. Client certificates can also be issued
and used as an authentication method for the client.


### HTTP authentication: out-of-the-box compatibility with identity providers

Using HTTP authentication schemes for user authentication allows implementing diverse authentication
mechanisms such as the classical password-based and public key authentication, but also popular
web authentication mechanisms such as OpenID Connect {{OpenID.Core}}, SAML2 {{OASIS.saml-core-2.0-os}} or the recent Passkeys/WebAuthn standard {{WebAuthn}}. All these authentication schemes are already deployed
for managing access to critical resources in different organizations. Sharing computing resources
using SSHv2 through these mechanisms generally requires the deployment of middlewares managing the
mapping between identities and SSH keys or certificates. Adding HTTP authentication to SSH
allows welcoming these authentication methods directly. As a proof-of-concept,
OpenID Connect has been implemented in our SSH3 prototype.


### URL multiplexing and undiscoverability

Relying on HTTP allows easily placing SSH endpoints as resources accessible through specific URLs.
First, it makes it easier to integrate SSH endpoints to existing web servers that already perform
user authentication and authorization. Second, it allows placing several SSH server instances on the same physical machine on the same port. This instances can run in different virtual machines, containers or
simply different users and be multiplexed on a URL-basis.
Finally, it allows placing SSH endpoints behind secret URLs, reducing the exposure of SSH hosts to
scanning and bruteforce attacks. This goes in line with the will of having undiscoverable resources
also tackled by other IETF working groups {{HTTP-SIGNATURE}}. This property is not provided by SSHv2 since
the SSHv2 server announces its SSH version string to any connected TCP client. If wanted, SSH3 hosts can be made
undistinguishable from any HTTP server.


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
as defined in {{HTTP-SEMANTICS}}, with no restriction on the
authentication scheme used. If no Authorization header is present in the
request or if the authentication
scheme is not supported by the server, the server SHOULD respond with a
401 (Unauthorized) response message. Once the user authentication is successful, the SSH3 server can process the request and start the conversation. This section only provides example user authentication
mechanisms. Other mechanisms may be proposed in the future in separate
documents. The two first examples are implemented by our current
prototype. The third example leverages the Signature authentication
scheme {{HTTP-SIGNATURE}} and will be preferred for public key
authentication in future versions of our prototype.

### Example: password authentication using HTTP Basic Authentication

Password-based authentication is performed using the HTTP
Basic authentication scheme {{HTTP-BASIC}}. The user-id part of the
`<credentials>` in the Authorization header defined in {{HTTP-BASIC}}
MUST be equivalent to
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

SSH channels can be opened on HTTP/3 client-initiated bidirectional
streams. By default, HTTP/3 considers every client-initiated
bidirectional stream as a request stream. Similarly to WebTransport,
SSH3 extends HTTP/3 using a specific signal value. An SSH3 client can open a stream with
this signal value to indicate that it is not a request stream and that
the remaining stream bytes will be used arbitrarily by the SSH3 protocol
to carry the content of a channel.
For experimental purpose, the signal value is chosen at random and will
change over time. The current signal value is `0xaf3627e6`. The content of an HTTP/3 stream carrying an SSH3
channel is illustrated below.

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

The first value sent on the HTTP/3 stream is the Signal Value. The
Channel Type is a UTF-8-encoded string whose length is defined
by the Channel Type Length field.

\[\[Note: SSHv2 uses text-based channel IDs. Should we keep that or
use somthing else instead ? If we change, we loose a 1-1 mapping with SSHv2.]]

The Maximum Message Size field defines the maximum size in bytes of
SSH messages.

The remaining bytes of the stream are interpreted as a sequence of SSH
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

The direct-tcp and direct-udp channels request TCP and UDP port
forwarding from a local port on the client towards a remote address
accessible from the remote host.
The reverse-tcp and reverse-udp channels are used to request
the forwarding of UDP packets and TCP connections from a specific port
on the remote host to the client.

### Messages {#messages}

Messages are exchanged over channels similarly to SSHv2. The same
messages
format as the one defined in {{SSH-CONNECT}} applies, with channel
numbers removed from the messages headers as channel run over dedicated
HTTP streams. Hereunder is an example showing the wire format of the
`exit-status` SSH message for SSH3. Its SSHv2 variant is described in
[Section 6.10](https://datatracker.ietf.org/doc/html/rfc4254#section-6.10) of {{SSH-CONNECT}}.

~~~~
ExitStatusMessage {
    Message Type (string) = "exit-status",
    Want Reply (bool) = false,
    Exit Status (i)
}
~~~~

# SSH3 and MASQUE

SSH3 shares common objectives with the MASQUE proxy {{MASQUE}} and while it
is currently out of scope of this introductory document, interactions between
the two protocols may exist in the future. For instance, a MASQUE endpoint
can be integrated with SSH3 to provide diverse forwarding services.
Another possible outcome is the integration of SSH3 in the MASQUE
family of proxies in the form of a "`CONNECT-SHELL`" endpoint.

# Version Negotiation

For SSH3 implementations to be able to follow the versions of this draft
while being interoperable with a large amount of peers, we define the
"`ssh-version`" header to list the supported draft versions. The value
of this field sent by the client is a comma-separated list of strings
representing the filenames of the supported drafts without the "`draft-`"
prefix.
For instance, SSH3 clients implementing this draft in versions 00 and 01
send the "`ssh-version: michel-ssh3-00,michel-ssh3-01`"
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
servers in a similar way to classical HTTPS servers. Using valid TLS certificates on the server allows their
automatic verification on the client with no explicit user action
required. Connecting an SSH3 client to a server with no valid
cerificate exposes the user to at best the same risk incurred by SSHv2
endpoints relying on Host keys: the user needs to manually validate the
certificate before connecting to avoid an attacker to impersonate the
server and access the keystrokes typed by the user during the
conversation.


# IANA Considerations

## HTTP Upgrade Token
This document will request IANA to register "ssh3" in the "HTTP Upgrade
Tokens" registry maintained at <https://www.iana.org/assignments/http-upgrade-tokens>.

\[\[Note: This may be removed if we decide to run SSH3 atop WebTransport instead of
HTTP/3 only.]]


--- back

# Acknowledgments
{:numbered="false"}

We warmly thank Maxime Piraux, Lucas Pardue and David Schinazi for their precious
comments on the document before the submission.
