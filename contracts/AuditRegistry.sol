// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title AuditRegistry
/// @notice On-chain storage for Mantle-Audit-AI audit results
/// @dev Each audit is recorded with severity counts and an IPFS report hash
contract AuditRegistry {
    struct AuditRecord {
        address auditor;        // Address of the auditing agent
        string  contractHash;   // keccak256 of audited contract source
        bytes32 reportHash;     // Hash of the IPFS CID
        uint8   criticalCount;
        uint8   highCount;
        uint8   mediumCount;
        uint8   lowCount;
        uint256 timestamp;
    }

    mapping(bytes32 => AuditRecord) public audits;
    bytes32[] public auditIds;
    address public owner;

    event AuditCompleted(
        bytes32 indexed auditId,
        address indexed auditor,
        string  contractHash,
        bytes32 reportHash
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Record a completed audit on-chain
    /// @param contractHash keccak256 hash of the audited contract source
    /// @param reportHash Hash of the IPFS CID containing the full report
    /// @param critical Number of Critical severity findings
    /// @param high Number of High severity findings
    /// @param medium Number of Medium severity findings
    /// @param low Number of Low severity findings
    /// @return auditId Unique identifier for this audit
    function recordAudit(
        string calldata contractHash,
        bytes32 reportHash,
        uint8 critical,
        uint8 high,
        uint8 medium,
        uint8 low
    ) external returns (bytes32 auditId) {
        auditId = keccak256(
            abi.encodePacked(contractHash, block.timestamp, msg.sender)
        );

        audits[auditId] = AuditRecord({
            auditor: msg.sender,
            contractHash: contractHash,
            reportHash: reportHash,
            criticalCount: critical,
            highCount: high,
            mediumCount: medium,
            lowCount: low,
            timestamp: block.timestamp
        });

        auditIds.push(auditId);

        emit AuditCompleted(auditId, msg.sender, contractHash, reportHash);
    }

    /// @notice Verify an audit record by ID
    /// @param auditId The audit identifier
    /// @return record The full audit record
    function verifyAudit(bytes32 auditId) external view returns (AuditRecord memory record) {
        record = audits[auditId];
        require(record.timestamp > 0, "Audit not found");
    }

    /// @notice Get total number of audits recorded
    function getAuditCount() external view returns (uint256) {
        return auditIds.length;
    }
}
