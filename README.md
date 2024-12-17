# TLS Router
This project implements a TLS reverse proxy that supports routing traffic via
the TLS connection parameters and supports ECH header decryption. This work was
inspired by the NGINX `ssl_preread` module but I wanted something that could be
a little bit more flexible in routing traffic via the TLS headers.

When ECH is used, this project operates as the Client-Facing server in the Split
Mode toplogy. The inner client hello will be decrypted and forwarded to the
matching backend server.

# Building
This project is written in Go, and can be built simply by calling `go build` in
the top level directory. This should produce the `tls-router` binary.

# Usage
TODO: Describe Me!

# ECH Setup

To setup ECH support, we must first generate an HPKE private key. This can be
accomplished by using the `-g` argument and providing a HPKE KEM algorithm to
use. For example
```
user@example.com:~$ ./tls-router -g x25519-hkdf-sha256 > ech-private.pem
user@example.com:~$ cat ech-private.pem
-----BEGIN HPKE PRIVATE KEY-----
Qs4r1UBZp+oSh1cEQ1UgZ5Gk6pJFBmrZSIdntskcnbc=
-----END HPKE PRIVATE KEY-----
```

We must then provide an `ech` configuration in the YAML document. The path to
the private key can be used as the `private_key_file` parameter for an ECH
configuration.

Next, we must configure our DNS records to include the `ech` parameter in an
`HTTPS` record. We can generate the `ech` record usig the `-s` argument as
follows:
```
user@example.com:~$ ./tls-router -c example.yaml -s
ech=AEv+DQBHAAAgACCrVhhlN1kc1CapEP/hcTNXrKl+LOzN3ZufjIapPCVMMQAMAAEAAQACAAIAAQADABBlY2gubWFuYXdvbGYubmV0AAA=
```

# Configuration

The configuration file is provided in YAML format and consists of three
sections:
 - `listen` describes the client-facing port that will listen for incoming
   connections.
 - `routes` describes the backend servers that will handle requests, and the
   rules for matching the connections that should route to thme.
 - `ech` describes the configuration to support a TLS1.3 encrypted client hello.

An example configuration file might look as follows:

```
listen:
  - :443

routes:
  main-page:
    sni: www.example.com
    targets: [ 192.168.1.123:8443 ]
  static-content:
    sni: static.example.com
    targets:
      - address: 192.168.1.111:8443
        weight: 100
      - address: 192.168.1.222:8443
        weight: 10
  acme-responder:
    alpn: acme-tls/1
    targets:
      - 192.168.1.42:10443

ech:
  - config_id: 0
    kem_id: x25519-hkdf-sha256
    cipher_suites:
      - hkdf-sha256,aes128gcm
      - hkdf-sha384,aes256gcm
      - hkdf-sha256,chacha20poly1035
    public_name: example.com
    private_key_file: ech-private.pem
```

## Listen

`listen` should contain an array of YAML strings. The expected syntax is
`[address]:port`, where `address` is an optional IPv4 or IPv6 address on the
local machine, and `port` is the TCP port number to listen for connections on.

## Routes
`routes` should contain a YAML dictionary. The key of the dictionary serves as
a label for the route, and the value contains a dictionary of TLS connection
parameters to match. Each parameter can be either a string, regular expression
or an array of strings or regular expressions.

The supported parameters include:
 - `sni` to match the Server Name extension.
 - `alpn` to match the Application Protocol Negotiation extension.
 - `ciphers` to match the client's supported cipher suites.

Each route must also contain a `targets` array. The `targets` should list the
backend servers to which the matching connections will be routed. Each target
can either be a string, or a YAML dictionary containing containing the following
values:
 - `address`: Destination address of the backend server.
 - `weight`: Weighting for load balancing (default 100, if not provided).

## ECH
`ech` should contain an array of YAML dictionaries. Each dict describes one
`ECHConfig` structure, and contains the following values:
 - `config_id`: An 8-bit unsigned integer identifying the configuration.
 - `kem_id`: The HPKE Key Encapsulation Mechanism to use for this config.
 - `cipher_suites`: A list of HPKE KDF and AEAD ciphers supported by this config. 
 - `public_name`: The server name to expect in the ClientHelloOuter.
 - `maximum_name_length`: The maximum expected server name in the ClientHelloInner.
 - `private_key`: The HPKE private key, either in base64 or in PEM encoding.
 - `private_key_file`: A path to the HPKE private key.

Only one of `private_key` or `private_key_file` should be provided.
