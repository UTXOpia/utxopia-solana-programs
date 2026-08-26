//! What does one BLAKE2b compression cost in BPF?
//!
//! Measured by differencing: run N compressions and N+M, subtract. That cancels the entrypoint,
//! instruction-data parsing and loop setup without having to model any of them, which is the same
//! method used for the Groth16 verifier number (97,159 CU) this is compared against.
//!
//! Equihash-200,9 verification evaluates ~512 compressions per header. The question is whether
//! that fits inside Solana's 1.4M CU per-instruction limit.

use mollusk_svm::Mollusk;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;

fn cu_for(mollusk: &Mollusk, pid: &Pubkey, mode: u8, rounds: u16) -> u64 {
    let mut data = vec![mode];
    data.extend_from_slice(&rounds.to_le_bytes());
    let ix = Instruction::new_with_bytes(*pid, &data, vec![]);
    let res = mollusk.process_instruction(&ix, &[]);
    assert!(
        !res.program_result.is_err(),
        "mode={mode} rounds={rounds} failed: {:?}",
        res.program_result
    );
    res.compute_units_consumed
}

#[test]
fn blake2b_compression_cost() {
    std::env::set_var("SBF_OUT_DIR", concat!(env!("CARGO_MANIFEST_DIR"), "/target/deploy"));
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "equihash_bench");

    let per_of = |mode: u8| {
        let c1 = cu_for(&mollusk, &pid, mode, 1);
        let c101 = cu_for(&mollusk, &pid, mode, 101);
        ((c101 - c1) / 100, c1, c101)
    };
    let (per, c1, c101) = per_of(0);
    let (sha, _, _) = per_of(1);
    let (keccak, _, _) = per_of(2);
    let (blake3, _, _) = per_of(3);

    let equihash_hashes = 512u64;
    let projected = per * equihash_hashes;
    const LIMIT: u64 = 1_400_000;
    const GROTH16: u64 = 97_159;

    println!("\n  BLAKE2b in BPF — measured\n");
    println!("    1 compression      {c1:>10} CU (includes entrypoint baseline)");
    println!("    101 compressions   {c101:>10} CU");
    println!("    per compression    {per:>10} CU  <- baseline cancelled");
    println!();
    println!("    Equihash-200,9 verification is ~{equihash_hashes} compressions:");
    println!("    projected          {projected:>10} CU");
    println!("    instruction limit  {LIMIT:>10} CU  ({:.1}% of budget)", projected as f64 / LIMIT as f64 * 100.0);
    println!("    Groth16 verify     {GROTH16:>10} CU  (for scale; measured 2026-08-25)");
    println!("    ratio to Groth16   {:>10.1}x", projected as f64 / GROTH16 as f64);
    println!();
    println!("  Same 128-byte block, hashed by a syscall instead:\n");
    println!("    sol_sha256         {sha:>10} CU");
    println!("    sol_keccak256      {keccak:>10} CU");
    println!("    sol_blake3         {blake3:>10} CU");
    println!("    BLAKE2b in BPF     {per:>10} CU   <- no syscall exists");
    println!();
    let hypothetical = blake3 * equihash_hashes;
    println!("    If BLAKE2b were a syscall priced like blake3:");
    println!("    Equihash would be  {hypothetical:>10} CU  ({:.1}% of budget, {:.0}x cheaper)",
        hypothetical as f64 / LIMIT as f64 * 100.0, projected as f64 / hypothetical as f64);
    println!();

    // Not an assertion about the answer — just that the measurement is meaningful.
    assert!(per > 0, "differencing produced no signal");
}
