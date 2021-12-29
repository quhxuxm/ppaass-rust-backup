# What is Ppaass?

Ppaass is a intranet penetration tool implemented based on Rust.

It contains 2 parts: 

* Proxy: Running outside the intranet to access the target network and relay the network connection to target that can not accessed by Agent.
* Agent: Running inside the intranet to access the Proxy and relay the network connection to Proxy

# Ppaass - Agent

Ppaass Agent is a application running inside intranet and it accept socks5 or http protocol and hand over the stream to proxy.
The stream pass to Proxy will be encrypted with AES, Blowfish, RSA.

# Pppaass - Proxy

Ppaass Proxy is a application running outside intranet and it accept the private protocol and hand over the stream to target.
