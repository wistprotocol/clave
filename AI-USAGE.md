# AI Usage

This file records the generative-AI involvement in this repository's
history from before per-commit provenance marking existed — every commit
up to and including the one introducing this file. From that point on,
commits with substantially AI-generated content name the model used in
an `Assisted-by:` git trailer.

## Record

Development in the covered period used Claude Fable 5
(`claude-fable-5`, Anthropic) via Claude Code, under human direction:
maintainers directed the work and reviewed and accepted every change
before it entered history. Delegated subagent tasks may have executed
on other Claude-family models (Claude Opus, Claude Sonnet) under
Fable 5's direction and final review, so provenance is recorded at the
orchestrator level.

AI-drafted: the Rust implementation of the aggregator service, its
tests, and documentation.

Human: the architecture and service design, operational policy choices
the protocol leaves open, and the review and acceptance of every
change. Conformance is defined outside this repository, by the WIST
spec repository's documents, schemas and test vectors; when
implementation and spec disagree, the spec wins.

## Copyright

The creative choices shaping this repository — its architecture, the
selection and arrangement of its contents, and the direction and
acceptance of every AI contribution — are its human maintainers'.
Dual-licensed under the terms in `LICENSE-MIT` and `LICENSE-APACHE`.
