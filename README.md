# What is Ppaass?

Ppaass is a intranet penetration tool implemented based on Rust + Tokio.

It contains 2 parts:

* Ppaass Proxy: Running outside the intranet to access the target network and relay the network connection to target that can not accessed
  by Agent.
* Ppaass Agent: Running inside the intranet to access the Proxy and relay the network connection to Proxy

# Ppaass - Agent

Ppaass Agent is an application running inside intranet and it accept socks5 or http protocol and hand over the stream to proxy. The stream
pass to Proxy will be encrypted with AES, Blowfish, RSA.

## Support protocol of Agent

The Ppaass Agent support multiple protocol to hand over the stream:

* HTTP proxy protocol
* Socks5 proxy protocol, currently it implements following process
    - Authenticate
    - Connect
    - Tcp relay
    - Udp associate
    - Udp relay

# Ppaass - Proxy

Ppaass Proxy is an application running outside intranet to accepts the private protocol and hand over the stream to target.
