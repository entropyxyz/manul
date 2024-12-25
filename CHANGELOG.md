# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.2.0] - in development

### Changed

- Removed `protocol::digest` re-export ([#75]).
- `digest` and `signature` are now re-exported from the top level instead of `session` ([#75]).
- `ProtocolError::verify_messages_constitute_error()` takes a new `shared_randomness` argument. ([#76])
- `Protocol` and `ProtocolError` are now generic over `Id`. ([#76])
- `ProtocolError::verify_messages_constitute_error()` takes a new `guilty_party` argument. ([#76])
- `Combinator`/`CombinatorEntryPoint` removed in favor of a single `ChainedMarker` trait. ([#76])


[#75]: https://github.com/entropyxyz/manul/pull/75
[#76]: https://github.com/entropyxyz/manul/pull/76


## [0.1.0] - 2024-11-19

### Changed

- `Session` is now generic over `SessionParameters` instead of a bunch of separate types. ([#36])
- `MessageBundle` is not generic anymore. ([#36])
- `ProcessedArtifact` is now also generic on `SessionParameters`. ([#37])
- Added a `Test` prefix to `testing::Signer`/`Verifier`/`Signature`/`Hasher` and renamed `TestingSessionParams` to `TestSessionParams`. ([#40])
- `SessionId::new()` renamed to `from_seed()`. ([#41])
- `FirstRound::new()` takes a `&[u8]` instead of a `SessionId` object. ([#41])
- The signatures of `Round::make_echo_broadcast()`, `Round::make_direct_message()`, and `Round::receive_message()`, take messages without `Option`s. ([#46])
- `Artifact::empty()` removed, the user should return `None` instead. ([#46])
- `EchoBroadcast` and `DirectMessage` now use `ProtocolMessagePart` trait for their methods. ([#47])
- Added normal broadcasts support in addition to echo ones; signatures of `Round` methods changed accordingly; added `Round::make_normal_broadcast()`. ([#47])
- Serialization format is a part of `SessionParameters` now; `Round` and `Protocol` methods receive dynamic serializers/deserializers. ([#33])
- Renamed `(Verified)MessageBundle` to `(Verified)Message`. Both are now generic over `Verifier`. ([#56])
- `Session::preprocess_message()` now returns a `PreprocessOutcome` instead of just an `Option`. ([#57])
- `Session::terminate_due_to_errors()` replaces `terminate()`; `terminate()` now signals user interrupt. ([#58])
- Renamed `FirstRound` trait to `EntryPoint`. ([#60])
- Added `Protocol` type to `EntryPoint`. ([#60])
- `EntryPoint` and `FinalizeOutcome::AnotherRound` now use a new `BoxedRound` wrapper type. ([#60])
- `PartyId` and `ProtocolError` are now bound on `Serialize`/`Deserialize`. ([#60])
- Entry points are now stateful; combinator API reworked accordingly. ([#68])
- `run_sync()` now returns an `ExecutionResult` object. ([#71])
- `testing` module and feature renamed to `dev` to avoid confusion with tests. ([#71])
- Correctness proofs are removed from the API. Consequently, `FinalizeError` is removed, and `Round::finalize()` returns a `Result<..., LocalError>`) ([#72])


### Added

- `SerializableMap` wrapper for `BTreeMap` supporting more formats and providing some safety features. (#[32])
- `DirectMessage::assert_is_none()` and `verify_is_some()`, same for `EchoBroadcast`. Users can now check that a part of the round message (echo or direct) is `None` as expected, and make a verifiable evidence if it is not. ([#46])
- Re-export `digest` from the `session` module. ([#56])
- Added `Message::destination()`. ([#56])
- `PartyId` trait alias for the combination of bounds needed for a party identifier. ([#59])
- An impl of `ProtocolError` for `()` for protocols that don't use errors. ([#60])
- A dummy `CorrectnessProof` trait. ([#60])
- A `misbehave` combinator, intended primarily for testing. ([#60])
- A `chain` combinator for chaining two protocols. ([#60])
- `EntryPoint::ENTRY_ROUND` constant. ([#60])
- `Round::echo_round_participation()`. ([#67])
- `SessionReport::result()`. ([#71])
- `utils::SerializableMap`. ([#74])


[#32]: https://github.com/entropyxyz/manul/pull/32
[#33]: https://github.com/entropyxyz/manul/pull/33
[#36]: https://github.com/entropyxyz/manul/pull/36
[#37]: https://github.com/entropyxyz/manul/pull/37
[#40]: https://github.com/entropyxyz/manul/pull/40
[#41]: https://github.com/entropyxyz/manul/pull/41
[#46]: https://github.com/entropyxyz/manul/pull/46
[#47]: https://github.com/entropyxyz/manul/pull/47
[#56]: https://github.com/entropyxyz/manul/pull/56
[#57]: https://github.com/entropyxyz/manul/pull/57
[#58]: https://github.com/entropyxyz/manul/pull/58
[#59]: https://github.com/entropyxyz/manul/pull/59
[#60]: https://github.com/entropyxyz/manul/pull/60
[#67]: https://github.com/entropyxyz/manul/pull/67
[#68]: https://github.com/entropyxyz/manul/pull/68
[#71]: https://github.com/entropyxyz/manul/pull/71
[#72]: https://github.com/entropyxyz/manul/pull/72
[#74]: https://github.com/entropyxyz/manul/pull/74


## [0.0.1] - 2024-10-12

Initial release.


[0.0.1]: https://github.com/entropyxyz/manul/releases/tag/v0.0.1
[0.1.0]: https://github.com/entropyxyz/manul/releases/tag/v0.1.0
