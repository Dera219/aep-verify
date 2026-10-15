# Vendored conformance vectors

The files under `v1.0.3-rc.2/` are verbatim copies of the A-Comm Evidence
Protocol conformance vectors, taken from

    https://github.com/A-Comm-Tech/a-comm-evidence-protocol/tree/main/vectors/v1.0.3-rc.2
    last upstream commit touching that directory: fd5174e5ef4245a2f5cb29e4a841ef7230eeac06 (2026-07-19)

They are Copyright 2025-2026 A-Comm Technologies, Inc. and licensed under the
Apache License, Version 2.0 (SPDX-License-Identifier: Apache-2.0), which is a
different license from the MIT license that covers the verifier code in this
repository. See the upstream LICENSE and NOTICE files.

SHA-256 of the vendored copies:

    b97625bfe54c46e55b60004bbcda34d8aa5b0966b1eb35da4a3b6b7facbe63e2  README.md
    71b9bde290586e6aba6e082cfc5d0c4d0c22cf9f3401103d47579e40925c078e  a-genesis.json
    6073f5551038e7727e46bc6cfa36bf22c5a2474038b2743a997faa5351fccb38  b-chain.json
    8152a6659187ea60d6bff39aea888172db03933b3927f3e0ddd31e6a7c165a15  h-canonicalization.json
    d7d804a96e66efb8f6973c984a6761ea86ef0ac8523434b57229cefa0934039e  keys.json

The Ed25519 seed in `keys.json` is a published TEST key. It must never be used
outside test vectors.
