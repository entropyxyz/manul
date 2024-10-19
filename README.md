# Round-based distributed protocols

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![License][license-image]
[![Build Status][build-image]][build-link]
[![Coveralls][coveralls-image]][coveralls-link]


*The body is round*

## Goals

- Sans-I/O API. That is, bring your own async libraries, or don't.
- Generic over signer/verifier/signature types, so you can use whatever your blockchain uses.
- Support parallelization where possible, to offload expensive cryptographic operations into spawned tasks (but since it's Sans-I/O, it's up to you to make use of that functionality).
- Provide tools for unit and integration testing of the protocols.
- Support generating malicious behavior proofs and correctness proofs with bundled signed messages.
- Support caching messages intended for the next round and then applying them when it starts (since some nodes can finalize a round before others and send out a new batch of messages).


## Assumptions

We try to find the balance between supporting the majority of protocols and keeping the API simple. Currently we operate under the following assumptions:

- A protocol consists of several rounds.
- A round generates messages to send out without any additional external input, then waits for messages from other parties. When it receives enough messages, it can be finalized.
- On finalization, a round can return the result, halt with an error, or continue to another round.
- A round can generate several direct messages (each going to a specific party).
- Additionally, a round can generate one echo-broadcasted message, for which it will be ensured that each party received the same message.


[crate-image]: https://img.shields.io/crates/v/manul.svg
[crate-link]: https://crates.io/crates/manul
[docs-image]: https://docs.rs/manul/badge.svg
[docs-link]: https://docs.rs/manul/
[license-image]: https://img.shields.io/crates/l/manul
[build-image]: https://github.com/entropyxyz/manul/actions/workflows/ci.yml/badge.svg?branch=master&event=push
[build-link]: https://github.com/entropyxyz/manul/actions?query=workflow%3Aci
[coveralls-image]: https://coveralls.io/repos/github/entropyxyz/manul/badge.svg?branch=master
[coveralls-link]: https://coveralls.io/github/entropyxyz/manul?branch=master
