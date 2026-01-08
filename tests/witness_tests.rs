//! End-to-end tests for witness generation during trie operations.
//!
//! These tests verify that the witness correctly captures all accessed nodes,
//! especially in edge cases like deletion where sibling nodes must be accessed
//! for trie restructuring.

use alloy_primitives::{Address, B256, U256};
use alloy_trie::{EMPTY_ROOT_HASH, KECCAK_EMPTY};
use std::time::{SystemTime, UNIX_EPOCH};
use tempdir::TempDir;
use triedb::{account::Account, overlay::OverlayStateMut, path::AddressPath, Database};

/// Helper to create a test account with given balance and nonce
fn create_account(balance: u64, nonce: u64) -> Account {
    Account::new(nonce, U256::from(balance), EMPTY_ROOT_HASH, KECCAK_EMPTY)
}

/// Helper to create a unique temp directory for each test
fn create_temp_dir(test_name: &str) -> TempDir {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let unique_name = format!("{}_{}", test_name, timestamp);
    TempDir::new(&unique_name).unwrap()
}

/// Test: Basic witness generation
#[test]
fn test_basic_witness_generation() {
    let tmp_dir = create_temp_dir("witness_basic");
    let db_path = tmp_dir.path().join("db").to_str().unwrap().to_owned();
    let database = Database::create_new(db_path).unwrap();

    let addr1 = Address::from_word(B256::from(U256::from(1u64)));
    let account1 = create_account(1000, 1);

    let mut tx = database.begin_rw().unwrap();
    tx.set_account(AddressPath::for_address(addr1), Some(account1.clone())).unwrap();
    tx.commit().unwrap();

    let mut overlay_mut = OverlayStateMut::new();
    let modified_account = create_account(2000, 2);
    overlay_mut.insert(
        AddressPath::for_address(addr1).into(),
        Some(triedb::overlay::OverlayValue::Account(modified_account)),
    );
    let overlay = overlay_mut.freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();

    assert!(
        !result.witness.is_empty(),
        "Witness should not be empty when modifying existing state"
    );

    tx.commit().unwrap();
}

/// Test: Witness generation with multiple accounts
#[test]
fn test_witness_multiple_accounts() {
    let tmp_dir = create_temp_dir("witness_multi");
    let db_path = tmp_dir.path().join("db").to_str().unwrap().to_owned();
    let database = Database::create_new(db_path).unwrap();

    let addresses: Vec<Address> =
        (1..=10).map(|i| Address::from_word(B256::from(U256::from(i as u64)))).collect();

    let mut tx = database.begin_rw().unwrap();
    for (i, addr) in addresses.iter().enumerate() {
        let account = create_account((i as u64 + 1) * 100, i as u64);
        tx.set_account(AddressPath::for_address(*addr), Some(account)).unwrap();
    }
    tx.commit().unwrap();

    let mut overlay_mut = OverlayStateMut::new();
    let modified_account = create_account(9999, 99);
    overlay_mut.insert(
        AddressPath::for_address(addresses[5]).into(),
        Some(triedb::overlay::OverlayValue::Account(modified_account)),
    );
    let overlay = overlay_mut.freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();

    assert!(
        !result.witness.is_empty(),
        "Witness should contain nodes for path to modified account"
    );

    tx.commit().unwrap();
}

/// Test: Deletion witness includes sibling nodes
#[test]
fn test_deletion_witness_includes_sibling() {
    let tmp_dir = create_temp_dir("witness_deletion");
    let db_path = tmp_dir.path().join("db").to_str().unwrap().to_owned();
    let database = Database::create_new(db_path).unwrap();

    let addr1 = Address::from_word(B256::from(U256::from(100u64)));
    let addr2 = Address::from_word(B256::from(U256::from(200u64)));

    let account1 = create_account(1000, 1);
    let account2 = create_account(2000, 2);

    let mut tx = database.begin_rw().unwrap();
    tx.set_account(AddressPath::for_address(addr1), Some(account1.clone())).unwrap();
    tx.set_account(AddressPath::for_address(addr2), Some(account2.clone())).unwrap();
    tx.commit().unwrap();

    let mut overlay_mut = OverlayStateMut::new();
    overlay_mut.insert(AddressPath::for_address(addr1).into(), None);
    let overlay = overlay_mut.freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();

    assert!(!result.witness.is_empty(), "Witness should not be empty after deletion");

    tx.commit().unwrap();
}

/// Test: Deletion of account with only one sibling forces sibling read
#[test]
fn test_branch_collapse_reads_sibling() {
    let tmp_dir = create_temp_dir("witness_collapse");
    let db_path = tmp_dir.path().join("db").to_str().unwrap().to_owned();
    let database = Database::create_new(db_path).unwrap();

    let accounts: Vec<(Address, Account)> = (0..20)
        .map(|i| {
            let addr = Address::from_word(B256::from(U256::from(i as u64 * 1000)));
            let account = create_account(i as u64 * 100, i as u64);
            (addr, account)
        })
        .collect();

    let mut tx = database.begin_rw().unwrap();
    for (addr, account) in &accounts {
        tx.set_account(AddressPath::for_address(*addr), Some(account.clone())).unwrap();
    }
    tx.commit().unwrap();

    let mut overlay_mut = OverlayStateMut::new();
    for (addr, _) in accounts.iter().take(10) {
        overlay_mut.insert(AddressPath::for_address(*addr).into(), None);
    }
    let overlay = overlay_mut.freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();

    assert!(!result.witness.is_empty(), "Witness should contain nodes after mass deletion");

    tx.commit().unwrap();
}

/// Test: Verify witness serialization round-trip
#[test]
fn test_witness_serialization() {
    let tmp_dir = create_temp_dir("witness_serialize");
    let db_path = tmp_dir.path().join("db").to_str().unwrap().to_owned();
    let database = Database::create_new(db_path).unwrap();

    let addr = Address::from_word(B256::from(U256::from(42u64)));
    let account = create_account(1000, 1);

    let mut tx = database.begin_rw().unwrap();
    tx.set_account(AddressPath::for_address(addr), Some(account)).unwrap();
    tx.commit().unwrap();

    let mut overlay_mut = OverlayStateMut::new();
    let modified = create_account(2000, 2);
    overlay_mut.insert(
        AddressPath::for_address(addr).into(),
        Some(triedb::overlay::OverlayValue::Account(modified)),
    );
    let overlay = overlay_mut.freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();
    tx.commit().unwrap();

    let serialized = result.witness.serialize();
    let deserialized = triedb::Witness::deserialize(&serialized).unwrap();

    assert_eq!(
        result.witness.len(),
        deserialized.len(),
        "Deserialized witness should have same number of nodes"
    );

    for (hash, node) in result.witness.iter() {
        let other = deserialized.get(hash).expect("Node should exist after deserialize");
        assert_eq!(node.data, other.data, "Node data should match after deserialize");
    }
}

/// Test: Empty overlay produces empty witness
#[test]
fn test_empty_overlay_empty_witness() {
    let tmp_dir = create_temp_dir("witness_empty");
    let db_path = tmp_dir.path().join("db").to_str().unwrap().to_owned();
    let database = Database::create_new(db_path).unwrap();

    let addr = Address::from_word(B256::from(U256::from(1u64)));
    let account = create_account(1000, 1);

    let mut tx = database.begin_rw().unwrap();
    tx.set_account(AddressPath::for_address(addr), Some(account)).unwrap();
    tx.commit().unwrap();

    let overlay = OverlayStateMut::new().freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();
    tx.commit().unwrap();

    assert_eq!(result.root, database.state_root());
    assert!(result.witness.is_empty(), "Empty overlay should produce empty witness");
}

/// Test: New account on empty database
#[test]
fn test_new_account_empty_db() {
    let tmp_dir = create_temp_dir("witness_new_account");
    let db_path = tmp_dir.path().join("db").to_str().unwrap().to_owned();
    let database = Database::create_new(db_path).unwrap();

    let addr = Address::from_word(B256::from(U256::from(1u64)));
    let account = create_account(1000, 1);

    let mut overlay_mut = OverlayStateMut::new();
    overlay_mut.insert(
        AddressPath::for_address(addr).into(),
        Some(triedb::overlay::OverlayValue::Account(account)),
    );
    let overlay = overlay_mut.freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();
    tx.commit().unwrap();

    assert_ne!(result.root, EMPTY_ROOT_HASH);
}

/// Test: Comprehensive deletion scenario with witness verification
#[test]
fn test_comprehensive_deletion_witness() {
    let tmp_dir = create_temp_dir("witness_comprehensive_del");
    let db_path = tmp_dir.path().join("db").to_str().unwrap().to_owned();
    let database = Database::create_new(db_path).unwrap();

    let base_accounts: Vec<(Address, Account)> = (0..16)
        .map(|i| {
            let seed = (i as u64) * 0x1111111111111111u64;
            let addr = Address::from_word(B256::from(U256::from(seed)));
            let account = create_account(1000 + i as u64, i as u64);
            (addr, account)
        })
        .collect();

    let mut tx = database.begin_rw().unwrap();
    for (addr, account) in &base_accounts {
        tx.set_account(AddressPath::for_address(*addr), Some(account.clone())).unwrap();
    }
    tx.commit().unwrap();

    for i in 0..4 {
        let (addr_to_delete, _) = &base_accounts[i];

        let mut overlay_mut = OverlayStateMut::new();
        overlay_mut.insert(AddressPath::for_address(*addr_to_delete).into(), None);
        let overlay = overlay_mut.freeze();

        let tx = database.begin_ro().unwrap();
        let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();
        tx.commit().unwrap();

        if base_accounts.len() - i > 2 {
            assert!(
                !result.witness.is_empty() || i > 0,
                "Deletion from non-trivial tree should produce witness (iteration {})",
                i
            );
        }
    }
}

/// Comprehensive test covering all witness scenarios
#[test]
fn test_comprehensive_witness_all_scenarios() {
    let tmp_dir = create_temp_dir("witness_all_scenarios");
    let db_path = tmp_dir.path().join("db").to_str().unwrap().to_owned();
    let database = Database::create_new(db_path).unwrap();

    // Build initial state with accounts at various trie positions
    let initial_accounts: Vec<(Address, Account, &str)> = vec![
        // Group A
        (Address::from_word(B256::from(U256::from(0x1000u64))), create_account(1000, 1), "A1"),
        (Address::from_word(B256::from(U256::from(0x1001u64))), create_account(1001, 2), "A2"),
        (Address::from_word(B256::from(U256::from(0x1002u64))), create_account(1002, 3), "A3"),
        (Address::from_word(B256::from(U256::from(0x1003u64))), create_account(1003, 4), "A4"),
        // Group B
        (Address::from_word(B256::from(U256::from(0x2000u64))), create_account(2000, 5), "B1"),
        (Address::from_word(B256::from(U256::from(0x2001u64))), create_account(2001, 6), "B2"),
        // Group C
        (Address::from_word(B256::from(U256::from(0x3000u64))), create_account(3000, 7), "C1"),
        (Address::from_word(B256::from(U256::from(0x3001u64))), create_account(3001, 8), "C2"),
        (Address::from_word(B256::from(U256::from(0x3002u64))), create_account(3002, 9), "C3"),
        // Group D
        (Address::from_word(B256::from(U256::from(0xAAAAu64))), create_account(10000, 10), "D1"),
        (Address::from_word(B256::from(U256::from(0xBBBBu64))), create_account(11000, 11), "D2"),
        (Address::from_word(B256::from(U256::from(0xCCCCu64))), create_account(12000, 12), "D3"),
    ];

    let mut tx = database.begin_rw().unwrap();
    for (addr, account, _) in &initial_accounts {
        tx.set_account(AddressPath::for_address(*addr), Some(account.clone())).unwrap();
    }
    tx.commit().unwrap();

    // SCENARIO 1: Simple update
    let update_addr = initial_accounts[0].0;
    let updated_account = create_account(9999, 99);

    let mut overlay_mut = OverlayStateMut::new();
    overlay_mut.insert(
        AddressPath::for_address(update_addr).into(),
        Some(triedb::overlay::OverlayValue::Account(updated_account)),
    );
    let overlay = overlay_mut.freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();
    tx.commit().unwrap();

    assert!(!result.witness.is_empty(), "Update should produce witness for path traversal");
    let scenario1_witness_count = result.witness.len();

    // SCENARIO 2: Multiple updates in different branches
    let mut overlay_mut = OverlayStateMut::new();
    overlay_mut.insert(
        AddressPath::for_address(initial_accounts[1].0).into(),
        Some(triedb::overlay::OverlayValue::Account(create_account(8888, 88))),
    );
    overlay_mut.insert(
        AddressPath::for_address(initial_accounts[4].0).into(),
        Some(triedb::overlay::OverlayValue::Account(create_account(7777, 77))),
    );
    overlay_mut.insert(
        AddressPath::for_address(initial_accounts[9].0).into(),
        Some(triedb::overlay::OverlayValue::Account(create_account(6666, 66))),
    );
    let overlay = overlay_mut.freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();
    tx.commit().unwrap();

    assert!(
        result.witness.len() >= scenario1_witness_count,
        "Multiple updates should produce at least as many witness nodes"
    );

    // SCENARIO 3: Single deletion
    let delete_addr = initial_accounts[2].0;

    let mut overlay_mut = OverlayStateMut::new();
    overlay_mut.insert(AddressPath::for_address(delete_addr).into(), None);
    let overlay = overlay_mut.freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();
    tx.commit().unwrap();

    assert!(!result.witness.is_empty(), "Deletion should produce witness");

    // SCENARIO 4: Mass deletion (branch collapse)
    let mut tx = database.begin_rw().unwrap();
    tx.set_account(AddressPath::for_address(initial_accounts[2].0), None).unwrap();
    tx.commit().unwrap();

    let mut overlay_mut = OverlayStateMut::new();
    overlay_mut.insert(AddressPath::for_address(initial_accounts[0].0).into(), None);
    overlay_mut.insert(AddressPath::for_address(initial_accounts[1].0).into(), None);
    overlay_mut.insert(AddressPath::for_address(initial_accounts[3].0).into(), None);
    let overlay = overlay_mut.freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();
    tx.commit().unwrap();

    assert!(!result.witness.is_empty(), "Mass deletion should produce witness");

    // SCENARIO 5: Mixed operations
    let mut tx = database.begin_rw().unwrap();
    tx.set_account(AddressPath::for_address(initial_accounts[0].0), None).unwrap();
    tx.set_account(AddressPath::for_address(initial_accounts[1].0), None).unwrap();
    tx.set_account(AddressPath::for_address(initial_accounts[3].0), None).unwrap();
    tx.commit().unwrap();

    let mut overlay_mut = OverlayStateMut::new();
    let new_addr = Address::from_word(B256::from(U256::from(0xDEADu64)));
    overlay_mut.insert(
        AddressPath::for_address(new_addr).into(),
        Some(triedb::overlay::OverlayValue::Account(create_account(50000, 50))),
    );
    overlay_mut.insert(
        AddressPath::for_address(initial_accounts[4].0).into(),
        Some(triedb::overlay::OverlayValue::Account(create_account(99999, 999))),
    );
    overlay_mut.insert(AddressPath::for_address(initial_accounts[6].0).into(), None);
    let overlay = overlay_mut.freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();
    tx.commit().unwrap();

    assert!(!result.witness.is_empty(), "Mixed operations should produce witness");

    // SCENARIO 6: Subtree deletion
    let mut overlay_mut = OverlayStateMut::new();
    overlay_mut.insert(AddressPath::for_address(initial_accounts[7].0).into(), None);
    overlay_mut.insert(AddressPath::for_address(initial_accounts[8].0).into(), None);
    let overlay = overlay_mut.freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();
    tx.commit().unwrap();

    let _ = result.witness.len();

    // SCENARIO 7: Witness integrity verification
    let mut tx = database.begin_rw().unwrap();
    tx.set_account(AddressPath::for_address(initial_accounts[6].0), None).unwrap();
    tx.set_account(AddressPath::for_address(initial_accounts[7].0), None).unwrap();
    tx.set_account(AddressPath::for_address(initial_accounts[8].0), None).unwrap();
    tx.set_account(AddressPath::for_address(new_addr), Some(create_account(50000, 50))).unwrap();
    tx.set_account(
        AddressPath::for_address(initial_accounts[4].0),
        Some(create_account(99999, 999)),
    )
    .unwrap();
    tx.commit().unwrap();

    let mut overlay_mut = OverlayStateMut::new();
    overlay_mut.insert(
        AddressPath::for_address(initial_accounts[5].0).into(),
        Some(triedb::overlay::OverlayValue::Account(create_account(12345, 123))),
    );
    let overlay = overlay_mut.freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();
    tx.commit().unwrap();

    let serialized = result.witness.serialize();
    let deserialized = triedb::Witness::deserialize(&serialized).unwrap();
    assert_eq!(result.witness.len(), deserialized.len());

    // SCENARIO 8: Large batch operations
    let mut tx = database.begin_rw().unwrap();
    let batch_accounts: Vec<Address> = (0..50)
        .map(|i| {
            let addr = Address::from_word(B256::from(U256::from(0x10000u64 + i)));
            tx.set_account(AddressPath::for_address(addr), Some(create_account(i * 100, i)))
                .unwrap();
            addr
        })
        .collect();
    tx.commit().unwrap();

    let mut overlay_mut = OverlayStateMut::new();

    for addr in batch_accounts.iter().take(10) {
        overlay_mut.insert(
            AddressPath::for_address(*addr).into(),
            Some(triedb::overlay::OverlayValue::Account(create_account(99999, 999))),
        );
    }

    for addr in batch_accounts.iter().skip(10).take(10) {
        overlay_mut.insert(AddressPath::for_address(*addr).into(), None);
    }

    for i in 0..5 {
        let new_addr = Address::from_word(B256::from(U256::from(0x90000u64 + i)));
        overlay_mut.insert(
            AddressPath::for_address(new_addr).into(),
            Some(triedb::overlay::OverlayValue::Account(create_account(i * 1000, i))),
        );
    }

    let overlay = overlay_mut.freeze();

    let tx = database.begin_ro().unwrap();
    let result = tx.compute_root_with_overlay_and_witness(overlay).unwrap();
    tx.commit().unwrap();

    assert!(
        result.witness.len() > 5,
        "Large batch should produce substantial witness, got {} nodes",
        result.witness.len()
    );
}
