# Manul examples

This crate illustrates the usage of `manul` for implementing distributed protocols.

The library itself takes the perspective of the protocol implementor, as they create a set
of `Round` impls and write unit-tests for them.

The integration tests are written from the perspective of the protocol user, emulating an
asynchronous execution of the protocol on multiple nodes.

To run the example, execute: `RUST_LOG=debug cargo t -p manul-example --test async_runner`
