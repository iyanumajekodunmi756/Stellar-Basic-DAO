//! DAO Governance Module — M-of-N Multisig Proposal Lifecycle
//!
//! Replaces single-admin governance with a threshold-based multisig system.
//! All privileged contract actions (pause, upgrade, fee config, admin rotation)
//! must go through a proposal → approval → execution flow.
//!
//! ## Proposal Lifecycle
//! ```text
//! create_proposal() → Pending
//!   approve_proposal() × M → Executable
//!     execute_proposal() → Executed
//!   cancel_proposal() → Cancelled (any signer, at any Pending state)
//! ```
//!
//! ## Storage Keys
//! - `DataKey::GovernanceSigners` — Vec<Address> signer set
//! - `DataKey::GovernanceThreshold` — u32 approval threshold
//! - `DataKey::Proposal(proposal_id)` — GovernanceProposal struct
//! - `DataKey::ProposalApproval(proposal_id, signer)` — bool (voted flag)

use soroban_sdk::{contracttype, vec, Address, BytesN, Env, Symbol, Vec};

use crate::errors::RustAcademyError;
use crate::storage::DataKey;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of signers in the governance council.
pub const MAX_SIGNERS: u32 = 10;

/// Maximum proposal validity window: 30 days in seconds.
pub const MAX_PROPOSAL_EXPIRY_SECS: u64 = 2_592_000;

/// TTL for active (Pending/Executable) proposals: 30 days in ledger-seconds.
pub const PROPOSAL_ACTIVE_TTL_SECS: u64 = 2_592_000;

/// TTL for terminal (Executed/Cancelled) proposals: 7 days in ledger-seconds.
pub const PROPOSAL_TERMINAL_TTL_SECS: u64 = 604_800;

/// TTL for signer set and threshold storage: 6 months in ledger-seconds.
pub const GOVERNANCE_CONFIG_TTL_SECS: u64 = 15_552_000;

/// Topic namespace for all governance events.
pub const TOPIC_GOVERNANCE: &str = "TOPIC_GOVERNANCE";

// ---------------------------------------------------------------------------
// Governance Proposal Action
// ---------------------------------------------------------------------------

/// All privileged actions that can be proposed and executed through governance.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalAction {
    /// Toggle the global contract pause state.
    SetPaused { paused: bool },
    /// Set granular pause flags for specific operations.
    SetPauseFlags { enable_mask: u64, disable_mask: u64 },
    /// Upgrade the contract WASM to a new hash.
    UpgradeContract { new_wasm_hash: BytesN<32> },
    /// Update the global platform fee configuration.
    SetFeeConfig { fee_bps: u32 },
    /// Override fee configuration for a specific token.
    SetPerAssetFee {
        token: Address,
        fee_bps: u32,
        arbiter_bps: u32,
    },
    /// Change the platform wallet address.
    SetPlatformWallet { wallet: Address },
    /// Transfer the admin role to a new address.
    SetAdmin { new_admin: Address },
    /// Grant a role to a target address.
    GrantRole { target: Address, role: u32 },
    /// Revoke a role from a target address.
    RevokeRole { target: Address, role: u32 },
    /// Replace the signer set and threshold.
    UpdateSignerSet {
        new_signers: Vec<Address>,
        new_threshold: u32,
    },
}

// ---------------------------------------------------------------------------
// Proposal Status
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalStatus {
    /// Awaiting sufficient approvals.
    Pending,
    /// Threshold met; ready for execution.
    Executable,
    /// Action has been applied to contract state.
    Executed,
    /// Cancelled by a signer before execution.
    Cancelled,
}

// ---------------------------------------------------------------------------
// Governance Proposal
// ---------------------------------------------------------------------------

/// A governance proposal stored on-chain.
#[contracttype]
#[derive(Clone, Debug)]
pub struct GovernanceProposal {
    /// Stable 32-byte identifier derived from the proposal content.
    pub proposal_id: BytesN<32>,
    /// The action to execute when the threshold is reached.
    pub action: ProposalAction,
    /// Address that created the proposal.
    pub proposer: Address,
    /// Current proposal lifecycle status.
    pub status: ProposalStatus,
    /// Ledger timestamp after which the proposal expires.
    pub expires_at: u64,
    /// Number of distinct approvals collected so far.
    pub approval_count: u32,
    /// Ledger timestamp when the proposal was created.
    pub created_at: u64,
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

/// Read the current signer set from persistent storage.
pub fn get_signer_set(env: &Env) -> Vec<Address> {
    env.storage()
        .persistent()
        .get(&DataKey::GovernanceSigners)
        .unwrap_or_else(|| vec![env])
}

/// Write the signer set to persistent storage with a 6-month TTL.
pub fn set_signer_set(env: &Env, signers: &Vec<Address>) {
    env.storage()
        .persistent()
        .set(&DataKey::GovernanceSigners, signers);
    env.storage().persistent().extend_ttl(
        &DataKey::GovernanceSigners,
        GOVERNANCE_CONFIG_TTL_SECS as u32,
        GOVERNANCE_CONFIG_TTL_SECS as u32,
    );
}

/// Read the current threshold from persistent storage.
pub fn get_threshold(env: &Env) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::GovernanceThreshold)
        .unwrap_or(1u32)
}

/// Write the threshold to persistent storage with a 6-month TTL.
pub fn set_threshold(env: &Env, threshold: u32) {
    env.storage()
        .persistent()
        .set(&DataKey::GovernanceThreshold, &threshold);
    env.storage().persistent().extend_ttl(
        &DataKey::GovernanceThreshold,
        GOVERNANCE_CONFIG_TTL_SECS as u32,
        GOVERNANCE_CONFIG_TTL_SECS as u32,
    );
}

/// Check whether an address is in the current signer set.
pub fn is_signer(env: &Env, address: &Address) -> bool {
    let signers = get_signer_set(env);
    for i in 0..signers.len() {
        if signers.get(i).unwrap() == *address {
            return true;
        }
    }
    false
}

/// Read a proposal from persistent storage.
pub fn get_proposal(env: &Env, proposal_id: &BytesN<32>) -> Option<GovernanceProposal> {
    env.storage()
        .persistent()
        .get(&DataKey::GovernanceProposal(proposal_id.clone()))
}

/// Write a proposal to persistent storage.
fn set_proposal(env: &Env, proposal: &GovernanceProposal, ttl_secs: u64) {
    let key = DataKey::GovernanceProposal(proposal.proposal_id.clone());
    env.storage().persistent().set(&key, proposal);
    env.storage()
        .persistent()
        .extend_ttl(&key, ttl_secs as u32, ttl_secs as u32);
}

/// Check whether a signer has already approved a proposal.
fn has_approved(env: &Env, proposal_id: &BytesN<32>, signer: &Address) -> bool {
    let key = DataKey::GovernanceApproval(proposal_id.clone(), signer.clone());
    env.storage().persistent().get(&key).unwrap_or(false)
}

/// Record a signer's approval in persistent storage.
fn record_approval(env: &Env, proposal_id: &BytesN<32>, signer: &Address) {
    let key = DataKey::GovernanceApproval(proposal_id.clone(), signer.clone());
    env.storage().persistent().set(&key, &true);
    env.storage().persistent().extend_ttl(
        &key,
        PROPOSAL_ACTIVE_TTL_SECS as u32,
        PROPOSAL_ACTIVE_TTL_SECS as u32,
    );
}

// ---------------------------------------------------------------------------
// Proposal ID derivation
// ---------------------------------------------------------------------------

/// Derive a deterministic 32-byte proposal_id from proposal content.
///
/// `proposal_id = SHA256(action_tag_symbol || proposer || nonce || valid_until)`
///
/// Inputs are serialized in a fixed layout so the same inputs always produce
/// the same ID, regardless of SDK version or field ordering.
pub fn derive_proposal_id(
    env: &Env,
    action_tag: Symbol,
    proposer: &Address,
    nonce: u64,
    valid_until: u64,
) -> BytesN<32> {
    use soroban_sdk::Bytes;

    let mut preimage = Bytes::new(env);

    // Append action tag bytes
    let tag_bytes: Bytes = action_tag.to_val().to_string(env).as_bytes().into();
    preimage.append(&tag_bytes);

    // Append proposer address bytes
    let proposer_bytes: Bytes = proposer.to_string().as_bytes().into();
    preimage.append(&proposer_bytes);

    // Append nonce as 8 big-endian bytes
    let nonce_bytes = nonce.to_be_bytes();
    preimage.push_back(nonce_bytes[0]);
    preimage.push_back(nonce_bytes[1]);
    preimage.push_back(nonce_bytes[2]);
    preimage.push_back(nonce_bytes[3]);
    preimage.push_back(nonce_bytes[4]);
    preimage.push_back(nonce_bytes[5]);
    preimage.push_back(nonce_bytes[6]);
    preimage.push_back(nonce_bytes[7]);

    // Append valid_until as 8 big-endian bytes
    let expiry_bytes = valid_until.to_be_bytes();
    preimage.push_back(expiry_bytes[0]);
    preimage.push_back(expiry_bytes[1]);
    preimage.push_back(expiry_bytes[2]);
    preimage.push_back(expiry_bytes[3]);
    preimage.push_back(expiry_bytes[4]);
    preimage.push_back(expiry_bytes[5]);
    preimage.push_back(expiry_bytes[6]);
    preimage.push_back(expiry_bytes[7]);

    env.crypto().sha256(&preimage)
}

/// Extract a stable action tag symbol from a ProposalAction variant.
pub fn action_tag(action: &ProposalAction) -> &'static str {
    match action {
        ProposalAction::SetPaused { .. } => "SetPaused",
        ProposalAction::SetPauseFlags { .. } => "SetPauseFlags",
        ProposalAction::UpgradeContract { .. } => "UpgradeContract",
        ProposalAction::SetFeeConfig { .. } => "SetFeeConfig",
        ProposalAction::SetPerAssetFee { .. } => "SetPerAssetFee",
        ProposalAction::SetPlatformWallet { .. } => "SetPlatformWallet",
        ProposalAction::SetAdmin { .. } => "SetAdmin",
        ProposalAction::GrantRole { .. } => "GrantRole",
        ProposalAction::RevokeRole { .. } => "RevokeRole",
        ProposalAction::UpdateSignerSet { .. } => "UpdateSignerSet",
    }
}

// ---------------------------------------------------------------------------
// Governance entry points
// ---------------------------------------------------------------------------

/// Initialize governance with an initial signer set and threshold.
///
/// Called once during `initialize()`. Seeds the legacy admin address as the
/// sole signer with `threshold = 1` for backward compatibility.
///
/// # Errors
/// - `InvalidSignerSet` — empty set, >10 signers, or zero-address in set
/// - `DuplicateSigner` — duplicate addresses in set
/// - `InvalidThreshold` — threshold is 0 or exceeds signer count
pub fn initialize_governance(
    env: &Env,
    signers: Vec<Address>,
    threshold: u32,
) -> Result<(), RustAcademyError> {
    validate_signer_set(env, &signers, threshold)?;
    set_signer_set(env, &signers);
    set_threshold(env, threshold);
    Ok(())
}

/// Create a new governance proposal.
///
/// The proposer is automatically counted as the first approval.
///
/// # Arguments
/// * `proposer` — must be a signer; must `require_auth()`
/// * `action` — the privileged action to gate
/// * `nonce` — per-signer unique value for replay protection
/// * `valid_until` — expiry timestamp (max 30 days from now)
///
/// # Errors
/// - `NotASigner` — proposer not in signer set
/// - `SignatureExpired` — `valid_until` is in the past
/// - `ExpiryTooFar` — `valid_until` more than 30 days away
/// - `NonceAlreadyUsed` — nonce already consumed for this signer
/// - `ProposalAlreadyExists` — derived `proposal_id` already in storage
pub fn create_proposal(
    env: &Env,
    proposer: Address,
    action: ProposalAction,
    nonce: u64,
    valid_until: u64,
) -> Result<BytesN<32>, RustAcademyError> {
    proposer.require_auth();

    // 1. Signer membership check
    if !is_signer(env, &proposer) {
        return Err(RustAcademyError::NotASigner);
    }

    let now = env.ledger().timestamp();

    // 2. Expiry in the past
    if now >= valid_until {
        return Err(RustAcademyError::SignatureExpired);
    }

    // 3. Expiry too far
    if valid_until - now > MAX_PROPOSAL_EXPIRY_SECS {
        return Err(RustAcademyError::ExpiryTooFar);
    }

    // 4. Nonce replay check
    crate::nonce::verify_and_consume(env, &proposer, nonce)?;

    // 5. Derive proposal_id
    let tag = Symbol::new(env, action_tag(&action));
    let proposal_id = derive_proposal_id(env, tag, &proposer, nonce, valid_until);

    // 6. Duplicate proposal_id check
    if get_proposal(env, &proposal_id).is_some() {
        return Err(RustAcademyError::ProposalAlreadyExists);
    }

    // 7. Store proposal + record proposer as first approval
    let proposal = GovernanceProposal {
        proposal_id: proposal_id.clone(),
        action,
        proposer: proposer.clone(),
        status: ProposalStatus::Pending,
        expires_at: valid_until,
        approval_count: 1,
        created_at: now,
    };
    set_proposal(env, &proposal, PROPOSAL_ACTIVE_TTL_SECS);
    record_approval(env, &proposal_id, &proposer);

    // 8. Emit ProposalCreated event
    emit_proposal_created(
        env,
        &proposal_id,
        &proposer,
        proposal.expires_at,
        action_tag(&proposal.action),
    );

    Ok(proposal_id)
}

/// Approve an existing proposal.
///
/// When the approval count reaches the threshold, status transitions to `Executable`.
///
/// # Errors
/// - `NotASigner` — caller not in signer set
/// - `ProposalNotFound` — no proposal for this ID
/// - `SignatureExpired` — proposal has expired
/// - `InvalidProposalState` — proposal is not `Pending`
/// - `AlreadyApproved` — caller already approved
pub fn approve_proposal(
    env: &Env,
    caller: Address,
    proposal_id: BytesN<32>,
) -> Result<(), RustAcademyError> {
    caller.require_auth();

    // 1. Signer membership
    if !is_signer(env, &caller) {
        return Err(RustAcademyError::NotASigner);
    }

    // 2. Proposal existence
    let mut proposal = get_proposal(env, &proposal_id).ok_or(RustAcademyError::ProposalNotFound)?;

    // 3. Expiry
    if env.ledger().timestamp() >= proposal.expires_at {
        return Err(RustAcademyError::SignatureExpired);
    }

    // 4. Status must be Pending
    if proposal.status != ProposalStatus::Pending {
        return Err(RustAcademyError::InvalidProposalState);
    }

    // 5. Duplicate approval
    if has_approved(env, &proposal_id, &caller) {
        return Err(RustAcademyError::AlreadyApproved);
    }

    // 6. Record approval
    record_approval(env, &proposal_id, &caller);
    proposal.approval_count += 1;

    // 7. Transition to Executable if threshold reached
    let threshold = get_threshold(env);
    if proposal.approval_count >= threshold {
        proposal.status = ProposalStatus::Executable;
    }

    set_proposal(env, &proposal, PROPOSAL_ACTIVE_TTL_SECS);

    emit_proposal_approved(
        env,
        &proposal_id,
        &caller,
        proposal.approval_count,
        threshold,
    );

    Ok(())
}

/// Execute a proposal that has reached the approval threshold.
///
/// Can be called by any address — no auth required for execution itself.
/// The action is applied atomically; if it fails, proposal state is unchanged.
///
/// # Errors
/// - `ProposalNotFound`
/// - `SignatureExpired`
/// - `InvalidProposalState`
/// - `InsufficientApprovals`
pub fn execute_proposal(env: &Env, proposal_id: BytesN<32>) -> Result<(), RustAcademyError> {
    // 1. Proposal existence
    let mut proposal = get_proposal(env, &proposal_id).ok_or(RustAcademyError::ProposalNotFound)?;

    // 2. Expiry
    if env.ledger().timestamp() >= proposal.expires_at {
        return Err(RustAcademyError::SignatureExpired);
    }

    // 3. Status
    if proposal.status != ProposalStatus::Pending && proposal.status != ProposalStatus::Executable {
        return Err(RustAcademyError::InvalidProposalState);
    }

    // 4. Approval count
    let threshold = get_threshold(env);
    if proposal.approval_count < threshold {
        return Err(RustAcademyError::InsufficientApprovals);
    }

    // 5. Apply action
    apply_action(env, &proposal.action)?;

    // 6. Mark executed
    proposal.status = ProposalStatus::Executed;
    set_proposal(env, &proposal, PROPOSAL_TERMINAL_TTL_SECS);

    emit_proposal_executed(
        env,
        &proposal_id,
        action_tag(&proposal.action),
        proposal.approval_count,
    );

    Ok(())
}

/// Cancel a pending proposal.
///
/// Only callable by a signer. The proposal must be in `Pending` status.
///
/// # Errors
/// - `NotASigner`
/// - `ProposalNotFound`
/// - `InvalidProposalState` — not in `Pending`
pub fn cancel_proposal(
    env: &Env,
    caller: Address,
    proposal_id: BytesN<32>,
) -> Result<(), RustAcademyError> {
    caller.require_auth();

    if !is_signer(env, &caller) {
        return Err(RustAcademyError::NotASigner);
    }

    let mut proposal = get_proposal(env, &proposal_id).ok_or(RustAcademyError::ProposalNotFound)?;

    if proposal.status != ProposalStatus::Pending {
        return Err(RustAcademyError::InvalidProposalState);
    }

    proposal.status = ProposalStatus::Cancelled;
    set_proposal(env, &proposal, PROPOSAL_TERMINAL_TTL_SECS);

    emit_proposal_cancelled(env, &proposal_id, &caller);

    Ok(())
}

// ---------------------------------------------------------------------------
// Action dispatch
// ---------------------------------------------------------------------------

/// Apply a proposal action to contract state.
///
/// This function is the central dispatch for all governance-gated privileged
/// operations. It is called atomically inside `execute_proposal()`.
fn apply_action(env: &Env, action: &ProposalAction) -> Result<(), RustAcademyError> {
    match action {
        ProposalAction::SetPaused { paused } => {
            crate::storage::set_paused(env, *paused);
            Ok(())
        }
        ProposalAction::SetPauseFlags {
            enable_mask,
            disable_mask,
        } => {
            crate::storage::apply_pause_flags(env, *enable_mask, *disable_mask);
            Ok(())
        }
        ProposalAction::SetFeeConfig { fee_bps } => {
            use crate::types::FeeConfig;
            let config = FeeConfig {
                fee_bps: *fee_bps,
                schema_version: crate::types::FEE_CONFIG_SCHEMA_VERSION,
            };
            crate::storage::set_fee_config(env, config);
            Ok(())
        }
        ProposalAction::SetPlatformWallet { wallet } => {
            crate::storage::set_platform_wallet(env, wallet);
            Ok(())
        }
        ProposalAction::SetAdmin { new_admin } => {
            crate::storage::set_admin(env, new_admin);
            Ok(())
        }
        ProposalAction::UpdateSignerSet {
            new_signers,
            new_threshold,
        } => {
            validate_signer_set(env, new_signers, *new_threshold)?;
            set_signer_set(env, new_signers);
            set_threshold(env, *new_threshold);
            emit_signer_set_updated(env, *new_threshold, new_signers.len());
            Ok(())
        }
        ProposalAction::GrantRole { target, role } => {
            use crate::types::Role;
            let r = u32_to_role(*role)?;
            crate::storage::grant_role(env, target, r);
            Ok(())
        }
        ProposalAction::RevokeRole { target, role } => {
            use crate::types::Role;
            let r = u32_to_role(*role)?;
            crate::storage::revoke_role(env, target, r);
            Ok(())
        }
        ProposalAction::SetPerAssetFee {
            token,
            fee_bps,
            arbiter_bps,
        } => {
            use crate::types::PerAssetFeeConfig;
            let config = PerAssetFeeConfig {
                fee_bps: *fee_bps,
                arbiter_bps: *arbiter_bps,
                ..Default::default()
            };
            crate::storage::set_per_asset_fee(env, token, config);
            Ok(())
        }
        ProposalAction::UpgradeContract { new_wasm_hash } => {
            // Upgrade is executed after the governance threshold is met.
            // The actual WASM swap happens here.
            env.deployer()
                .update_current_contract_wasm(new_wasm_hash.clone());
            Ok(())
        }
    }
}

/// Convert a u32 role discriminant to a typed `Role` enum.
fn u32_to_role(role: u32) -> Result<crate::types::Role, RustAcademyError> {
    match role {
        1 => Ok(crate::types::Role::Admin),
        2 => Ok(crate::types::Role::Operator),
        3 => Ok(crate::types::Role::Arbiter),
        _ => Err(RustAcademyError::InternalError),
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a proposed signer set and threshold.
///
/// # Errors
/// - `InvalidSignerSet` — empty, >10 signers, or any zero-address
/// - `DuplicateSigner` — duplicate addresses
/// - `InvalidThreshold` — threshold is 0 or > signer count
fn validate_signer_set(
    env: &Env,
    signers: &Vec<Address>,
    threshold: u32,
) -> Result<(), RustAcademyError> {
    let len = signers.len();

    if len == 0 || len > MAX_SIGNERS {
        return Err(RustAcademyError::InvalidSignerSet);
    }

    if threshold == 0 || threshold > len {
        return Err(RustAcademyError::InvalidThreshold);
    }

    // Check for duplicates (O(n²) — acceptable for n ≤ 10)
    for i in 0..len {
        let a = signers.get(i).unwrap();
        for j in (i + 1)..len {
            let b = signers.get(j).unwrap();
            if a == b {
                return Err(RustAcademyError::DuplicateSigner);
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

fn emit_proposal_created(
    env: &Env,
    proposal_id: &BytesN<32>,
    proposer: &Address,
    expires_at: u64,
    action_tag_str: &str,
) {
    let topics = (
        Symbol::new(env, TOPIC_GOVERNANCE),
        Symbol::new(env, "ProposalCreated"),
        proposal_id.clone(),
        proposer.clone(),
    );
    let data = (
        Symbol::new(env, action_tag_str),
        expires_at,
        env.ledger().timestamp(),
        1u32, // schema_version
    );
    env.events().publish(topics, data);
}

fn emit_proposal_approved(
    env: &Env,
    proposal_id: &BytesN<32>,
    approver: &Address,
    approval_count: u32,
    threshold: u32,
) {
    let topics = (
        Symbol::new(env, TOPIC_GOVERNANCE),
        Symbol::new(env, "ProposalApproved"),
        proposal_id.clone(),
        approver.clone(),
    );
    let data = (approval_count, threshold, env.ledger().timestamp(), 1u32);
    env.events().publish(topics, data);
}

fn emit_proposal_executed(
    env: &Env,
    proposal_id: &BytesN<32>,
    action_tag_str: &str,
    approval_count: u32,
) {
    let topics = (
        Symbol::new(env, TOPIC_GOVERNANCE),
        Symbol::new(env, "ProposalExecuted"),
        proposal_id.clone(),
    );
    let data = (
        Symbol::new(env, action_tag_str),
        approval_count,
        env.ledger().timestamp(),
        1u32,
    );
    env.events().publish(topics, data);
}

fn emit_proposal_cancelled(env: &Env, proposal_id: &BytesN<32>, cancelled_by: &Address) {
    let topics = (
        Symbol::new(env, TOPIC_GOVERNANCE),
        Symbol::new(env, "ProposalCancelled"),
        proposal_id.clone(),
        cancelled_by.clone(),
    );
    let data = (env.ledger().timestamp(), 1u32);
    env.events().publish(topics, data);
}

fn emit_signer_set_updated(env: &Env, new_threshold: u32, signer_count: u32) {
    let topics = (
        Symbol::new(env, TOPIC_GOVERNANCE),
        Symbol::new(env, "SignerSetUpdated"),
    );
    let data = (new_threshold, signer_count, env.ledger().timestamp(), 1u32);
    env.events().publish(topics, data);
}
