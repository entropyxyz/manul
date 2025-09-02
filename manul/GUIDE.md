# Getting started building protocols with `manul`

This guide provides a step-by-step explanation of how to build protocols using `manul`. See the [examples/] folder for concrete examples.



Building a protocol with `manul` involves defining the protocol's overall structure, breaking it down into rounds with specific communication and logic, defining the messages exchanged, providing an entry point to initialize the protocol, configuring session parameters for cryptography and data handling, and finally using the provided utilities to execute the protocol (or write your own).

Refer to the [crate documentation](https://docs.rs/manul) for more details and advanced topics.

## 1. Define Your Protocol Structure ([`Protocol`])

Start by defining a struct to represent your protocol. This struct will implement the [`Protocol`] trait, serving as a container for the protocol's core properties:

```rust,ignore
#[derive(Debug)]
pub struct MyProtocol;

impl<Id> Protocol<Id> for MyProtocol {
    type Result = SomeResultType;
    // ... other required trait methods and types ...
}
```

Key aspects:

- **[`type Result`]**: This associated type defines the final output of a successful protocol execution. In the case of the Dining Cryptographers Problem, it's a tuple of bools representing each cryptographer's perspective on the outcome.
- **Error Handling (Advanced)**: In more realistic protocols, the [`Protocol`] trait is where you would define error types and misbehavior reporting; when not needed, there's a [`NoProtocolErrors`] convenience type.

## 2. Define Your Rounds ([`Round`])

Protocols are broken down into a series of rounds. For each round, create a struct implementing the [`Round`] trait:

```rust,ignore
#[derive(Debug, Clone, Serialize)]
pub struct Round1 { /* ... */ }

impl Round<DinerId> for Round1 {
    type Protocol = MyProtocol;
    // ... required trait methods ...
}
```

Key aspects of a [`Round`]:

- **[`type Protocol`]**: This associated type links the round to the overall protocol it belongs to.
- **State Management**: Rounds often need to maintain some state specific to their execution. This state is often stored within the round struct itself, either as members or within one or more helper structs.
- **[`transition_info()`]**: Defines how this round connects to other rounds in the protocol flow. It specifies the possible predecessor rounds (`parents`), successor rounds (`children`), and whether this round can produce a final result (`may_produce_result`). For simple linear flows, [`TransitionInfo::new_linear`] and [`TransitionInfo::new_linear_terminating`] simplify the setup.
- **[`communication_info()`]**: Defines who the participants in this round communicates with, including message destinations and expected senders. It also allows specifying participation in "echo rounds" for certain broadcast scenarios.
- **Message Handling**: Rounds define how messages are created and processed. Users are expected to create their own message types, allowing maximum flexibility in how they are constructed, processed and serialized/deserialized.
  - **[`make_direct_message()`]**: Creates messages sent point-to-point to specific parties, optionally including an [`Artifact`] for storing associated data related to that message.
  - **[`make_echo_broadcast()`]/[`make_normal_broadcast()`]**: Create broadcast messages; [`make_echo_broadcast`] is for messages that require confirmation of reception (echoes), while [`make_normal_broadcast`] is for fire-and-forget broadcasts.
  - **[`receive_message()`]**: Processes incoming messages, deserializing the relevant part of the [`ProtocolMessage`] and extracting necessary information. It returns a [`Payload`], which acts as a container for data passed to the `finalize` method.
- **[`finalize()`]**: This is where the round concludes its logic. It has access to all [`Payload`]s received from other parties and any [`Artifact`]s created during message sending. It either returns the next round to execute ([`FinalizeOutcome::AnotherRound`]) or the final protocol result ([`FinalizeOutcome::Result`]).

## 3. Define Your Messages

Create structs to represent the data exchanged between parties. These structs should implement `Serialize` and `Deserialize` from the `serde` crate:

```rust,no_run
# use serde::{Serialize, Deserialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct Round1Message {
    cointoss: bool,
}
```

## 4. Create an Entry Point ([`EntryPoint`])

The [`EntryPoint`] defines how a protocol execution begins and is the only round that can be created outside the protocol flow. The [`EntryPoint`] can carry data, e.g. configuration or external initialization data.

```rust,ignore
#[derive(Debug, Clone)]
struct MyEntryPoint { /* ... */ }

impl EntryPoint<DinerId> for MyEntryPoint {
    type Protocol = MyProtocol;
    // ... required trait methods ...
}
```

Key aspects:

- **[`type Protocol`]**: Links the entry point to the protocol it initiates.
- **[`entry_round_id()`]**: Specifies the ID of the initial round.
- **[`make_round()`]**: This method is called at the start of a session to construct the first round of the protocol, initializing any necessary state.

## 5. Define Session Parameters ([`SessionParameters`])

The [`SessionParameters`] trait defines crucial parameters for a protocol session, including:

```rust,no_run
# use manul::session::SessionParameters;
# use manul::dev;
# type MySigner = dev::TestSigner;
# type MyId = u8;
# type MyVerifier = dev::TestVerifier;
# type MySignature = dev::TestSignature;
# type MyHasher = dev::TestHasher;
# type MyWireFormat = dev::BinaryFormat;
#[derive(Debug, Clone, Copy)]
pub struct MySessionParams;

impl SessionParameters for MySessionParams {
    type Signer = MySigner;
    type Verifier = MyVerifier;
    type Signature = MySignature;
    type Digest = MyHasher;
    type WireFormat = MyWireFormat;
}
```

Key types:

- **`Signer` / `Verifier` / `Signature`**:  Handle cryptographic signing and verification, ensuring message authenticity.
- **`Digest`**:  Specifies the hashing algorithm used for message digests.
- **`WireFormat`**:  Determines how messages are serialized and deserialized for transmission over the network (e.g., [`BinaryFormat`], [`HumanReadableFormat`]).

## 6. Run the Protocol

Use the provided execution utilities (e.g., [`run_sync`] for synchronous execution) to execute your protocol:

```rust,ignore
let results = run_sync::<_, DiningSessionParams>(&mut OsRng, entry_points)
    .expect("Failed to run the protocol")
    .results()
    .expect("The protocol executed but failed to produce results");
```

This function takes a vector of `(Signer, EntryPoint)` pairs (one for each participant) and session parameters, runs the protocol, and returns the final results.

[examples/]: https://github.com/entropyxyz/manul/tree/master/examples
[`Protocol`]: crate::protocol::Protocol
[`type Result`]: crate::protocol::Protocol::Result
[`NoProtocolErrors`]: crate::protocol::NoProtocolErrors
[`Round`]: crate::protocol::Round
[`type Protocol`]: crate::protocol::Round::Protocol
[`transition_info()`]: crate::protocol::Round::transition_info
[`TransitionInfo::new_linear`]: crate::protocol::TransitionInfo::new_linear
[`TransitionInfo::new_linear_terminating`]: crate::protocol::TransitionInfo::new_linear_terminating
[`communication_info()`]: crate::protocol::Round::communication_info
[`make_direct_message()`]: crate::protocol::Round::make_direct_message
[`make_echo_broadcast()`]: crate::protocol::Round::make_echo_broadcast
[`make_echo_broadcast`]: crate::protocol::Round::make_echo_broadcast
[`make_normal_broadcast()`]: crate::protocol::Round::make_normal_broadcast
[`make_normal_broadcast`]: crate::protocol::Round::make_normal_broadcast
[`receive_message()`]: crate::protocol::Round::receive_message
[`ProtocolMessage`]: crate::protocol::ProtocolMessage
[`finalize()`]: crate::protocol::Round::finalize
[`Artifact`]: crate::protocol::Round::Artifact
[`FinalizeOutcome::AnotherRound`]: crate::protocol::FinalizeOutcome::AnotherRound
[`FinalizeOutcome::Result`]: crate::protocol::FinalizeOutcome::Result
[`EntryPoint`]: crate::protocol::EntryPoint
[`type Protocol`]: crate::protocol::EntryPoint::Protocol
[`entry_round_id()`]: crate::protocol::EntryPoint::entry_round_id
[`make_round()`]: crate::protocol::EntryPoint::make_round
[`SessionParameters`]: crate::session::SessionParameters
[`Payload`]: crate::protocol::Round::Payload
[`run_sync`]: crate::session::run_sync]
[`BinaryFormat`]: crate::dev::BinaryFormat
[`HumanReadableFormat`]: crate::dev::HumanReadableFormat
