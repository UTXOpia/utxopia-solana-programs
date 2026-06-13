//! Error definitions for UTXOPIA program

use pinocchio::program_error::ProgramError;
use thiserror::Error;

/// Custom error codes for UTXOPIA
/// Starting at 6000 to avoid conflicts with system errors
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum UTXOpiaError {
    #[error("Pool is paused")]
    PoolPaused = 6000,

    #[error("Deposit amount too small")]
    AmountTooSmall = 6001,

    #[error("Deposit amount too large")]
    AmountTooLarge = 6002,

    #[error("Invalid Merkle proof")]
    InvalidMerkleProof = 6003,

    #[error("Nullifier already used (double-spend attempt)")]
    NullifierAlreadyUsed = 6004,

    #[error("Commitment not found in Merkle tree")]
    CommitmentNotFound = 6005,

    #[error("Invalid commitment hash")]
    InvalidCommitment = 6006,

    #[error("Invalid Bitcoin address")]
    InvalidBtcAddress = 6007,

    #[error("Redemption request not found")]
    RedemptionNotFound = 6008,

    #[error("Redemption already completed")]
    RedemptionAlreadyCompleted = 6009,

    #[error("Redemption in invalid state")]
    InvalidRedemptionState = 6010,

    #[error("Unauthorized")]
    Unauthorized = 6011,

    #[error("Insufficient balance")]
    InsufficientBalance = 6012,

    #[error("Arithmetic overflow")]
    Overflow = 6013,

    #[error("Invalid proof length")]
    InvalidProofLength = 6014,

    #[error("Deposit has already been minted")]
    AlreadyMinted = 6015,

    #[error("Amount must be greater than zero")]
    ZeroAmount = 6016,

    #[error("Invalid Bitcoin block header")]
    InvalidBlockHeader = 6017,

    #[error("Insufficient confirmations")]
    InsufficientConfirmations = 6018,

    #[error("Invalid SPV proof")]
    InvalidSpvProof = 6019,

    #[error("Commitment tree is full")]
    TreeFull = 6020,

    #[error("Invalid root")]
    InvalidRoot = 6021,

    #[error("Invalid ZK proof")]
    InvalidZkProof = 6022,

    #[error("ZK proof verification failed")]
    ZkVerificationFailed = 6023,

    #[error("Account not initialized")]
    NotInitialized = 6024,

    #[error("Account already initialized")]
    AlreadyInitialized = 6025,

    #[error("Invalid account owner")]
    InvalidAccountOwner = 6026,

    #[error("Invalid account data")]
    InvalidAccountData = 6027,

    #[error("Invalid stealth OP_RETURN data")]
    InvalidStealthOpReturn = 6028,

    #[error("Stealth data not found in transaction")]
    StealthDataNotFound = 6029,

    #[error("Insufficient funds in shielded pool")]
    InsufficientFunds = 6030,

    #[error("Redemption cancel not allowed")]
    RedemptionCancelNotAllowed = 6031,

    #[error("Redemption SPV verification failed")]
    RedemptionSpvFailed = 6033,

    #[error("Redemption BTC output not found in transaction")]
    RedemptionOutputNotFound = 6034,

    // Security validation errors (6060-6069)
    #[error("Account is not writable")]
    AccountNotWritable = 6060,

    #[error("Invalid token mint")]
    InvalidMint = 6061,

    #[error("Demo mode disabled on mainnet")]
    DemoDisabledOnMainnet = 6062,

    #[error("Account not rent exempt")]
    NotRentExempt = 6063,

    #[error("Duplicate accounts detected")]
    DuplicateAccounts = 6064,

    #[error("Account is closed")]
    AccountClosed = 6065,

    #[error("Invalid VK registry for circuit variant")]
    InvalidVkRegistry = 6066,

    #[error("Invalid bound parameters hash")]
    InvalidBoundParams = 6067,

    #[error("Redemption processing timeout exceeded")]
    RedemptionTimeout = 6068,

    #[error("JoinSplit dimensions exceed transaction size limit")]
    JoinSplitTooLarge = 6069,

    #[error("Redemption BTC output does not match expected address/amount")]
    RedemptionOutputMismatch = 6070,

    #[error("Block difficulty does not match expected value")]
    DifficultyMismatch = 6071,

    #[error("Timelock period has not elapsed")]
    TimelockNotElapsed = 6072,

    #[error("No pending pool update proposal")]
    NoPendingProposal = 6073,

    #[error("Deposit already verified (duplicate)")]
    DuplicateDeposit = 6074,

    #[error("Invalid UTXO record")]
    InvalidUtxo = 6075,

    #[error("UTXO is not in Unspent status")]
    UtxoNotUnspent = 6076,

    #[error("Pool script mismatch (instruction data vs on-chain config)")]
    PoolScriptMismatch = 6077,

    #[error("Taproot output key verification failed (npk does not match deposit address)")]
    TaprootVerificationFailed = 6078,

    // Multi-token errors (6080-6089)
    #[error("Token is disabled")]
    TokenDisabled = 6080,

    #[error("Invalid vault account")]
    InvalidVault = 6081,

    #[error("Deposit amount out of configured range")]
    AmountOutOfRange = 6082,

    #[error("Deposit cap exceeded for this token")]
    DepositCapExceeded = 6083,

    #[error("Insufficient accumulated fees")]
    InsufficientFees = 6084,

    #[error("Invalid PDA derivation")]
    InvalidPDA = 6085,

    // Ika dWallet integration errors (6086+)
    #[error("Redemption amount exceeds policy limit")]
    RedemptionAmountExceedsLimit = 6086,

    #[error("Computed miner fee exceeds policy limit")]
    RedemptionFeeExceedsLimit = 6087,

    #[error("Required Ika CPI accounts missing from accounts slice")]
    IkaCpiAccountsMissing = 6088,

    #[error("Invalid token config limits (min/max/cap)")]
    InvalidTokenConfig = 6089,
}

impl From<UTXOpiaError> for ProgramError {
    fn from(e: UTXOpiaError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
