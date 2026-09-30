// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IntegrityLedger
/// @notice On-chain anchor for the SHA-256 fingerprint of a monitored file.
///
/// Trust model (the "two-key" rule):
///   1. Only the developer (owner) can open an update window -> authorizeUpdate()
///   2. The monitoring agent can then commit exactly ONE new hash -> updateHash()
///   3. Committing the hash consumes the approval (flag resets to false)
///
/// Any hash change that arrives without step 1 is, by definition, tampering.
contract IntegrityLedger {
    // ----------------------------------------------------------------- state
    address public owner;            // developer wallet allowed to approve updates
    string private trustedHash;      // current known-good SHA-256 (hex string)
    bool public isUpdateAuthorized;  // true = an approved update window is open

    // ---------------------------------------------------------------- events
    // Events are the immutable audit trail the dashboard renders.
    event UpdateAuthorized(address indexed by, uint256 timestamp);
    event HashAnchored(string newHash, address indexed by, uint256 timestamp);
    event TamperDetected(string observedHash, string trustedHash, address indexed reporter, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "IntegrityLedger: caller is not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // ----------------------------------------------------------------- reads
    function getTrustedHash() external view returns (string memory) {
        return trustedHash;
    }

    // ---------------------------------------------------------------- writes
    /// @notice Developer approval: opens a one-shot window for a new hash.
    function authorizeUpdate() external onlyOwner {
        isUpdateAuthorized = true;
        emit UpdateAuthorized(msg.sender, block.timestamp);
    }

    /// @notice Commit a new trusted hash. Reverts unless an approval is pending.
    function updateHash(string calldata newHash) external {
        require(isUpdateAuthorized, "IntegrityLedger: update not authorized");
        trustedHash = newHash;
        isUpdateAuthorized = false; // approval is single-use
        emit HashAnchored(newHash, msg.sender, block.timestamp);
    }

    /// @notice Agent alert: permanently records an unauthorized hash on-chain.
    function reportTamper(string calldata observedHash) external {
        emit TamperDetected(observedHash, trustedHash, msg.sender, block.timestamp);
    }
}
