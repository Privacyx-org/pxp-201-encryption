// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IPxp201Registry.sol";

/// @title Pxp201Registry
/// @notice Minimal on-chain registry for PXP-201 envelopes (v0.1).
/// Stores references + commitments only (no secrets, no wrapped keys).
contract Pxp201Registry is IPxp201Registry {
    error AlreadyPublished(bytes32 recordId);
    error NotPublisher(bytes32 recordId);
    error InvalidUri();
    error InvalidCipher();
    error InvalidCiphertextHash();
    error InvalidAccessCommitment();

    struct Record {
        address publisher;
        string uri;
        uint8 cipher;
        bytes32 ciphertextHash;
        bytes32 aadHash;
        bytes32 accessCommitment;
        uint64 createdAt;
        bool revoked;
    }

    mapping(bytes32 => Record) private _records;

    function publish(
        bytes32 recordId,
        string calldata uri,
        uint8 cipher,
        bytes32 ciphertextHash,
        bytes32 aadHash,
        bytes32 accessCommitment
    ) external override {
        if (_records[recordId].publisher != address(0)) revert AlreadyPublished(recordId);
        if (bytes(uri).length < 3) revert InvalidUri();

        // v0.1: 1 = AES-256-GCM
        if (cipher != 1) revert InvalidCipher();

        if (ciphertextHash == bytes32(0)) revert InvalidCiphertextHash();
        if (accessCommitment == bytes32(0)) revert InvalidAccessCommitment();

        uint64 ts = uint64(block.timestamp);

        _records[recordId] = Record({
            publisher: msg.sender,
            uri: uri,
            cipher: cipher,
            ciphertextHash: ciphertextHash,
            aadHash: aadHash,
            accessCommitment: accessCommitment,
            createdAt: ts,
            revoked: false
        });

        emit Pxp201Published(
            recordId,
            msg.sender,
            uri,
            cipher,
            ciphertextHash,
            aadHash,
            accessCommitment,
            ts
        );
    }

    function revoke(bytes32 recordId) external override {
        Record storage r = _records[recordId];
        if (r.publisher == address(0) || r.publisher != msg.sender) revert NotPublisher(recordId);

        r.revoked = true;
        emit Pxp201Revoked(recordId, msg.sender, uint64(block.timestamp));
    }

    function getRecord(bytes32 recordId)
        external
        view
        override
        returns (
            address publisher,
            string memory uri,
            uint8 cipher,
            bytes32 ciphertextHash,
            bytes32 aadHash,
            bytes32 accessCommitment,
            uint64 createdAt,
            bool revoked
        )
    {
        Record storage r = _records[recordId];
        return (
            r.publisher,
            r.uri,
            r.cipher,
            r.ciphertextHash,
            r.aadHash,
            r.accessCommitment,
            r.createdAt,
            r.revoked
        );
    }
}
