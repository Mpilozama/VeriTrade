// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title VeriTrade Registry
 * @notice Immutable on-chain registry for AI-generated trade compliance audit hashes.
 *         Every hash anchored here is a cryptographic proof that an AI decision
 *         existed at a specific point in time and has not been altered since.
 * @dev Deployed on Ethereum Sepolia Testnet for hackathon demo.
 */
contract VeriTradeRegistry {

    // ─── State ────────────────────────────────────────────────────────────────

    /// @notice The platform administrator (deployer)
    address public owner;

    /// @notice Total number of audit hashes anchored on-chain
    uint256 public totalAnchored;

    /**
     * @notice Core storage: maps a SHA-256 audit hash (as bytes32) to its anchor metadata.
     * @dev bytes32 is the natural Solidity type for a 256-bit value.
     */
    struct AuditRecord {
        bool     exists;          // Whether this hash has been registered
        address  anchoredBy;      // The customs agent / wallet that submitted it
        uint256  blockNumber;     // Block at time of anchoring
        uint256  timestamp;       // Unix timestamp of anchoring
        string   supplierName;    // Human-readable label (not used for verification)
        string   verdict;         // "CLEARED" | "REVIEW" | "FLAGGED"
    }

    mapping(bytes32 => AuditRecord) public auditRecords;

    // ─── Events ───────────────────────────────────────────────────────────────

    /**
     * @notice Emitted when an audit hash is successfully anchored.
     * @param auditHash   The SHA-256 hash of the AI audit record
     * @param anchoredBy  The address that submitted the transaction
     * @param supplierName Human-readable supplier identifier
     * @param verdict     The AI compliance verdict
     * @param timestamp   Unix timestamp of the anchoring
     */
    event HashAnchored(
        bytes32 indexed auditHash,
        address indexed anchoredBy,
        string  supplierName,
        string  verdict,
        uint256 timestamp
    );

    /**
     * @notice Emitted when a duplicate anchor attempt is detected (already on-chain).
     * @param auditHash The hash that was already registered
     */
    event DuplicateAnchorAttempt(bytes32 indexed auditHash, address attemptedBy);

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
        totalAnchored = 0;
    }

    // ─── Core Functions ───────────────────────────────────────────────────────

    /**
     * @notice Anchor an AI audit hash onto the blockchain.
     * @param _hexHash     The 64-character hex SHA-256 hash string, converted to bytes32.
     *                     Frontend converts: ethers.utils.id(hexString) → bytes32
     * @param _supplierName  Human-readable supplier name for the UI
     * @param _verdict       The AI verdict string ("CLEARED", "REVIEW", or "FLAGGED")
     * @dev Anyone with a wallet can anchor a hash. The caller is the accountability trail.
     */
    function anchorHash(
        bytes32 _hexHash,
        string memory _supplierName,
        string memory _verdict
    ) external returns (bool) {
        // Prevent re-anchoring an existing hash (immutability guarantee)
        if (auditRecords[_hexHash].exists) {
            emit DuplicateAnchorAttempt(_hexHash, msg.sender);
            revert("VeriTrade: Hash already anchored. Record is immutable.");
        }

        // Store the audit record permanently on-chain
        auditRecords[_hexHash] = AuditRecord({
            exists:       true,
            anchoredBy:   msg.sender,
            blockNumber:  block.number,
            timestamp:    block.timestamp,
            supplierName: _supplierName,
            verdict:      _verdict
        });

        // Increment global counter
        totalAnchored += 1;

        // Emit event for UI to listen to
        emit HashAnchored(_hexHash, msg.sender, _supplierName, _verdict, block.timestamp);

        return true;
    }

    /**
     * @notice Verify whether an audit hash exists on-chain.
     * @param _hexHash The bytes32 hash to look up.
     * @return exists       Whether the hash is registered
     * @return anchoredBy   Who submitted it
     * @return blockNumber  The block it was anchored in
     * @return timestamp    Unix timestamp of anchoring
     * @return verdict      The recorded AI verdict
     */
    function verifyHash(bytes32 _hexHash)
        external
        view
        returns (
            bool    exists,
            address anchoredBy,
            uint256 blockNumber,
            uint256 timestamp,
            string memory verdict
        )
    {
        AuditRecord memory record = auditRecords[_hexHash];
        return (
            record.exists,
            record.anchoredBy,
            record.blockNumber,
            record.timestamp,
            record.verdict
        );
    }

    /**
     * @notice Convenience: check if a hash is on-chain (gas-efficient boolean check).
     */
    function isAnchored(bytes32 _hexHash) external view returns (bool) {
        return auditRecords[_hexHash].exists;
    }
}
