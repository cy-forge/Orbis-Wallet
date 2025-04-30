use argent::presets::argent_account::ArgentAccount;
use argent::signer::signer_signature::{Signer, StarknetSigner, starknet_signer_from_pubkey};
use starknet::VALIDATED;
use super::setup::{
    utils::{to_starknet_signatures, to_starknet_signer_signatures},
    constants::{GUARDIAN, OWNER, GUARDIAN_BACKUP, WRONG_OWNER, WRONG_GUARDIAN, tx_hash},
    account_test_setup::{
        ITestArgentAccountDispatcher, ITestArgentAccountDispatcherTrait, initialize_account,
        initialize_account_without_guardian, initialize_account_with
    }
};

#[test]
fn valid_no_guardian() {
    let account = initialize_account_without_guardian();
    let signatures = to_starknet_signatures(array![OWNER()]);
    assert_eq!(account.is_valid_signature(tx_hash, signatures), VALIDATED, "invalid signature");
}

#[test]
fn valid_with_guardian() {
    let signatures = to_starknet_signatures(array![OWNER(), GUARDIAN()]);
    assert_eq!(initialize_account().is_valid_signature(tx_hash, signatures), VALIDATED, "invalid signature");
}

#[test]
fn valid_with_guardian_backup() {
    let account = initialize_account_with(OWNER().pubkey, 1);
    let guardian_backup = Option::Some(starknet_signer_from_pubkey(GUARDIAN_BACKUP().pubkey));
    account.change_guardian_backup(guardian_backup);
    let signatures = to_starknet_signatures(array![OWNER(), GUARDIAN_BACKUP()]);
    assert_eq!(account.is_valid_signature(tx_hash, signatures), VALIDATED, "invalid signature");
}

#[test]
fn invalid_hash_1() {
    let account = initialize_account_without_guardian();
    let signatures = to_starknet_signatures(array![OWNER()]);
    assert_eq!(account.is_valid_signature(0, signatures), 0, "invalid signature");
}

#[test]
fn invalid_hash_2() {
    let account = initialize_account_without_guardian();
    let signatures = to_starknet_signatures(array![OWNER()]);
    assert_eq!(account.is_valid_signature(123, signatures), 0, "invalid signature");
}

#[test]
fn invalid_owner_without_guardian() {
    let account = initialize_account_without_guardian();
    let signatures = to_starknet_signer_signatures(array![1, 2, 3]);
    assert_eq!(account.is_valid_signature(tx_hash, signatures), 0, "invalid signature");
    let signatures = to_starknet_signatures(array![WRONG_OWNER()]);
    assert_eq!(account.is_valid_signature(tx_hash, signatures), 0, "invalid signature");
    let signatures = to_starknet_signer_signatures(
        array![GUARDIAN().pubkey, GUARDIAN_BACKUP().sig.r, GUARDIAN_BACKUP().sig.s]
    );
    assert_eq!(account.is_valid_signature(tx_hash, signatures), 0, "invalid signature");
}

#[test]
fn invalid_owner_with_guardian() {
    let account = initialize_account();
    let signatures = to_starknet_signer_signatures(
        array![1, 2, 3, GUARDIAN_BACKUP().pubkey, GUARDIAN_BACKUP().sig.r, GUARDIAN_BACKUP().sig.s]
    );
    assert_eq!(account.is_valid_signature(tx_hash, signatures), 0, "invalid signature");
    let signatures = to_starknet_signatures(array![WRONG_OWNER(), GUARDIAN_BACKUP()]);
    account.is_valid_signature(tx_hash, signatures);
}

#[test]
fn valid_owner_with_invalid_guardian() {
    let account = initialize_account();
    let signatures = to_starknet_signer_signatures(array![OWNER().pubkey, OWNER().sig.r, OWNER().sig.s, 1, 2, 3]);
    assert_eq!(account.is_valid_signature(tx_hash, signatures), 0, "invalid signature 1");
    let signatures = to_starknet_signer_signatures(array![OWNER().pubkey, OWNER().sig.r, OWNER().sig.s, 25, 42, 69]);
    assert_eq!(account.is_valid_signature(tx_hash, signatures), 0, "invalid signature 2");
    let signatures = to_starknet_signatures(array![OWNER(), WRONG_GUARDIAN()]);
    assert_eq!(account.is_valid_signature(tx_hash, signatures), 0, "invalid signature 3");
    let signatures = to_starknet_signatures(array![OWNER(), OWNER()]);
    assert_eq!(account.is_valid_signature(tx_hash, signatures), 0, "invalid signature 4");
}

#[test]
fn invalid_owner_with_invalid_guardian() {
    let account = initialize_account();
    let signatures = to_starknet_signer_signatures(array![1, 2, 3, 4, 5, 6]);
    assert_eq!(account.is_valid_signature(tx_hash, signatures), 0, "invalid signature 1");
    let signatures = to_starknet_signer_signatures(array![2, 42, 99, 6, 534, 123]);
    assert_eq!(account.is_valid_signature(tx_hash, signatures), 0, "invalid signature 2");
    let signatures = to_starknet_signer_signatures(
        array![WRONG_OWNER().pubkey, WRONG_OWNER().sig.r, WRONG_OWNER().sig.s, 1, 2, 3]
    );
    assert_eq!(account.is_valid_signature(tx_hash, signatures), 0, "invalid signature 3");
    let signatures = to_starknet_signer_signatures(
        array![1, 2, 3, WRONG_GUARDIAN().pubkey, WRONG_GUARDIAN().sig.r, WRONG_GUARDIAN().sig.s]
    );
    assert_eq!(account.is_valid_signature(tx_hash, signatures), 0, "invalid signature 4");
    let signatures = to_starknet_signatures(array![WRONG_OWNER(), WRONG_GUARDIAN()]);
    assert_eq!(account.is_valid_signature(tx_hash, signatures), 0, "invalid signature 5");
}

#[test]
#[should_panic(expected: ('argent/invalid-signature-format',))]
fn invalid_empty_signature_without_guardian() {
    let account = initialize_account_without_guardian();
    let signatures = array![];
    account.is_valid_signature(tx_hash, signatures);
}

#[test]
#[should_panic(expected: ('argent/invalid-signature-length',))]
fn invalid_signature_length_without_guardian() {
    let account = initialize_account_without_guardian();
    let signatures = to_starknet_signatures(array![OWNER(), GUARDIAN_BACKUP()]);
    account.is_valid_signature(tx_hash, signatures);
}

#[test]
#[should_panic(expected: ('argent/invalid-signature-format',))]
fn invalid_empty_signature_with_guardian() {
    let account = initialize_account();
    let signatures = array![];
    account.is_valid_signature(tx_hash, signatures);
}

#[test]
#[should_panic(expected: ('argent/invalid-signature-length',))]
fn invalid_signature_length_with_guardian() {
    let account = initialize_account();
    let signatures = to_starknet_signatures(array![OWNER()]);
    account.is_valid_signature(tx_hash, signatures);
}

#[test]
#[should_panic(expected: ('argent/invalid-signature-length',))]
fn invalid_signature_length_with_owner_and_guardian_and_backup() {
    let account = initialize_account_with(OWNER().pubkey, 1);
    let guardian_backup = starknet_signer_from_pubkey(GUARDIAN_BACKUP().pubkey);
    account.change_guardian_backup(Option::Some(guardian_backup));
    let signatures = to_starknet_signatures(array![OWNER(), GUARDIAN(), GUARDIAN_BACKUP()]);
    account.is_valid_signature(tx_hash, signatures);
}
