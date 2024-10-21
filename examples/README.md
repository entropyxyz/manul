This crate illustrates the usage of `manul` for implementing distributed protocols.

The library itself is the perspective of the protocol implementor, where they create a set of `Round` impls and write unit-tests for them.

The integration tests are the perspective of the protocol user, emulating an asynchronous execution of the protocol on multiple nodes.
