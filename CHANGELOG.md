# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.2] - In development

### Changed

- `Session` is now generic over `SessionParameters` instead of a bunch of separate types. ([#36])
- `MessageBundle` is not generic anymore. ([#36])
- `ProcessedArtifact` is now also generic on `SessionParameters`. ([#37])


### Added

- `SerializableMap` wrapper for `BTreeMap` supporting more formats and providing some safety features. (#[32])


[#32]: https://github.com/entropyxyz/manul/pull/32
[#36]: https://github.com/entropyxyz/manul/pull/36
[#37]: https://github.com/entropyxyz/manul/pull/37


## [0.0.1] - 2024-10-12

Initial release.


[0.0.1]: https://github.com/entropyxyz/manul/releases/tag/v0.0.1
