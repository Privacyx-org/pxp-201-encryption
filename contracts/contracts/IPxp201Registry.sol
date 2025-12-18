// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IPxp201Registry
/// @notice Minimal on-chain registry for PXP-201 envelopes (v0.1).
/// Stores references + commitments only (no secrets, no wrapped keys).
interface IPxp201Registry {
    /// @notice Emitted when a record is published.
    /// @param recordId Unique id (bytes32) chosen by publisher (e.g., sha256(envelope canonical bytes)).
    /// @param publisher msg.sender
    /// @param uri Storage pointer to ciphertext (ipfs://, ar://, https://, onchain://...)
    /// @param cipher Cipher id (v0.1: 1 = AES-256-GCM)
    /// @param ciphertextHash sha3-256(ciphertext bytes)
    /// @param aadHash sha3-256(aad bytes) or 0x0 if none
    /// @param accessCommitment commitment to access block (e.g., sha256(canonical access JSON))
    /// @param createdAt unix seconds
    event Pxp201Published(
        bytes32 indexed recordId,
        address indexed publisher,
        string uri,
        uint8 cipher,
        bytes32 ciphertextHash,
        bytes32 aadHash,
        bytes32 accessCommitment,
        uint64 createdAt
    );

    /// @notice Emitted when a record is deprecated/revoked by publisher.
    event Pxp201Revoked(bytes32 indexed recordId, address indexed publisher, uint64 revokedAt);

    /// @notice Publish a new PXP-201 record.
    /// @dev recordId MUST be unique. Implementations SHOULD revert if recordId already exists.
    function publish(
        bytes32 recordId,
        string calldata uri,
        uint8 cipher,
        bytes32 ciphertextHash,
        bytes32 aadHash,
        bytes32 accessCommitment
    ) external;

    /// @notice Revoke a previously published record (publisher-only in implementations).
    function revoke(bytes32 recordId) external;

    /// @notice Get basic record data.
    function getRecord(bytes32 recordId)
        external
        view
        returns (
            address publisher,
            string memory uri,
            uint8 cipher,
            bytes32 ciphertextHash,
            bytes32 aadHash,
            bytes32 accessCommitment,
            uint64 createdAt,
            bool revoked
        );
}
