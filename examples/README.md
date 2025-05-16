# User's Guide: Building Protocols with `manul`

This guide provides a step-by-step explanation of how to build protocols using `manul`, using the Dining Cryptographers example as a reference.

## 1. Define Your Protocol Structure (`Protocol`)

Start by defining a struct to represent your protocol. This struct will implement the `Protocol` trait, serving as a container for the protocol's core properties:

```rust,ignore
#[derive(Debug)]
pub struct DiningCryptographersProtocol;

impl<Id> Protocol<Id> for DiningCryptographersProtocol {
    type Result = (bool, bool, bool);
    // ... other required trait methods ...
}
```

Key aspects:

- **`type Result`**: This associated type defines the final output of a successful protocol execution. In this case, it's a tuple of three booleans representing each cryptographer's perspective on the outcome.
- **Error Handling (Advanced)**: In more complex protocols, the `Protocol` trait also handles error types and misbehavior reporting, which are simplified to `NoProtocolErrors` in this example.
- **Message Validation (Advanced)**: The methods `verify_direct_message_is_invalid`, `verify_echo_broadcast_is_invalid`, and `verify_normal_broadcast_is_invalid` are used for validating message contents during evidence verification in more complex scenarios.

## 2. Define Your Rounds (`Round`)

Protocols are broken down into a series of rounds. For each round, create a struct implementing the `Round` trait:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct Round1 { /* ... */ }

impl Round<DinerId> for Round1 {
    type Protocol = DiningCryptographersProtocol;
    // ... required trait methods ...
}
```

Key aspects of a `Round`:

- **`type Protocol`**: This associated type links the round to the overall protocol it belongs to.
- **State Management**: Rounds often need to maintain some state specific to their execution. This state is stored within the round struct itself (e.g., `diner_id`, `own_toss`, `paid` in `Round1`).
- **`transition_info()`**: Crucially defines how this round connects to other rounds in the protocol flow. It specifies the possible predecessor rounds (`parents`), successor rounds (`children`), and whether this round can produce a final result (`may_produce_result`). For simple linear flows, `TransitionInfo::new_linear` and `TransitionInfo::new_linear_terminating` simplify this.
- **`communication_info()`**: Defines who this round communicates with, including message destinations and expected senders. It also allows specifying participation in "echo rounds" for certain broadcast scenarios.
- **Message Handling**: Rounds define how they create and process messages.
  - **`make_direct_message()`**: Creates messages sent point-to-point to specific parties, optionally including an `Artifact` for storing associated data related to that message.
  - **`make_echo_broadcast()`/`make_normal_broadcast()`**: Create broadcast messages. `make_echo_broadcast` is for messages that require confirmation of reception (echoes), while `make_normal_broadcast` is for fire-and-forget broadcasts.
  - **`receive_message()`**: Processes incoming messages, deserializing the relevant part of the `ProtocolMessage` and extracting necessary information. It returns a `Payload`, which acts as a container for data passed to the `finalize` method.
- **`finalize()`**: This is where the round concludes its logic. It has access to all `Payload`s received from other parties and any `Artifact`s created during message sending. It either returns the next round to execute (`FinalizeOutcome::AnotherRound`) or the final protocol result (`FinalizeOutcome::Result`).

## 3. Define Your Messages

Create structs to represent the data exchanged between parties. These structs should implement `Serialize` and `Deserialize` from the `serde` crate:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct Round1Message {
    toss: bool,
}
```

## 4. Create an Entry Point (`EntryPoint`)

The `EntryPoint` defines how a protocol execution begins:

```rust
#[derive(Debug, Clone)]
struct DiningEntryPoint { /* ... */ }

impl EntryPoint<DinerId> for DiningEntryPoint {
    type Protocol = DiningCryptographersProtocol;
    // ... required trait methods ...
}
```

Key aspects:

- **`type Protocol`**: Links the entry point to the protocol it initiates.
- **`entry_round_id()`**: Specifies the ID of the initial round.
- **`make_round()`**: This method is called at the start of a session to construct the first round of the protocol, initializing any necessary state.

## 5. Define Session Parameters (`SessionParameters`)

The `SessionParameters` trait defines crucial parameters for a protocol session, including:

```rust
#[derive(Debug, Clone, Copy)]
pub struct DiningSessionParams;

impl SessionParameters for DiningSessionParams {
    type Signer = Diner;
    type Verifier = DinerId;
    type Signature = DinerSignature;
    type Digest = TestHasher;
    type WireFormat = BinaryFormat;
}
```

Key types:

- **`Signer` / `Verifier` / `Signature`**:  Handle cryptographic signing and verification, ensuring message authenticity.
- **`Digest`**:  Specifies the hashing algorithm used for message digests.
- **`WireFormat`**:  Determines how messages are serialized and deserialized for transmission over the network (e.g., `BinaryFormat`, `HumanReadableFormat`).

## 6. Run the Protocol

Use the provided execution utilities (e.g., `run_sync` for synchronous execution) to execute your protocol:

```rust
let results = run_sync::<_, DiningSessionParams>(&mut OsRng, entry_points)
    .expect("Failed to run the protocol")
    .results()
    .expect("The protocol executed but failed to produce results");
```

This function takes a vector of `(Signer, EntryPoint)` pairs (one for each participant) and session parameters, runs the protocol, and returns the final results.

**In summary,** building a protocol with `manul` involves defining the protocol's overall structure, breaking it down into rounds with specific communication and logic, defining the messages exchanged, providing an entry point to initialize the protocol, configuring session parameters for cryptography and data handling, and finally using the provided utilities to execute the protocol.
