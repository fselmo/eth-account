import glob
import json
import os

import pytest
import yaml
from eth_utils import (
    ValidationError,
    to_bytes,
)
from hexbytes import (
    HexBytes,
)
from toolz import (
    merge,
)

from eth_account import (
    Account,
)
from eth_account.typed_transactions import (
    BlobTransaction,
)

TEST_DATA_PATH = os.path.join(os.path.dirname(__file__), "_test_data")
SIGNED_TX_PATH = os.path.join(TEST_DATA_PATH, "signed_tx.txt")
BLOB_DATA_1_PATH = os.path.join(TEST_DATA_PATH, "blob_data_1.txt")
BLOB_DATA_1_SIGNED_PATH = os.path.join(
    TEST_DATA_PATH, "blob_data_1_signed.txt"
)
ZERO_BLOB_EIP7594_SIGNED_PATH = os.path.join(
    TEST_DATA_PATH, "zero_blob_eip7594_signed.txt"
)
CONSENSUS_SPEC_TESTS_PATH = os.path.join(
    TEST_DATA_PATH,
    "consensus_spec_tests",
    "fulu",
    "kzg",
    "compute_cells_and_kzg_proofs",
)
GO_ETH_KZG_COMPUTED_PATH = os.path.join(
    TEST_DATA_PATH, "go_eth_kzg_computed.json"
)

TEST_ACCT = Account.from_key(
    "0x4646464646464646464646464646464646464646464646464646464646464646"
)

ZERO_BLOB = f"0x{'00' * 32 * 4096}"
ZERO_BLOB_VERSIONED_HASH = (
    "0x010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014"
)
ZERO_BLOB_COMMITMENT_AND_PROOF_HASH = "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"  # noqa: E501
BLOB_TX_DICT = {
    "chainId": 1,
    "nonce": 1,
    "maxPriorityFeePerGas": 50,
    "maxFeePerGas": 1000,
    "gas": 100000,
    "to": "0x45Ae5777c9b35Eb16280e423b0d7c91C06C66B58",
    "value": 1,
    "data": "0x52fdfc072182654f",
    "maxFeePerBlobGas": 100,
}


def test_validation_when_blobs_are_present_with_incorrect_versioned_hashes_in_tx_dict():
    tx_dict_with_wrong_versioned_hashes = merge(
        BLOB_TX_DICT, {"blobVersionedHashes": [f"0x{'00' * 32}"]}
    )
    with pytest.raises(
        ValidationError,
        match=(
            "`blobVersionedHashes` value defined in transaction does not match "
            "versioned hashes computed from blobs."
        ),
    ):
        BlobTransaction.from_dict(
            tx_dict_with_wrong_versioned_hashes,
            blobs=[to_bytes(hexstr=ZERO_BLOB)],
        )


def test_blobs_commitments_proofs_and_hashes_from_blobs():
    # test that when correct blobVersionedHashes value is passed into tx dict,
    # validation does not raise
    correct_versioned_hashes = [ZERO_BLOB_VERSIONED_HASH]
    tx_dict_with_correct_versioned_hashes = merge(
        BLOB_TX_DICT, {"blobVersionedHashes": correct_versioned_hashes}
    )

    # test does not raise
    tx = BlobTransaction.from_dict(
        tx_dict_with_correct_versioned_hashes,
        blobs=[to_bytes(hexstr=ZERO_BLOB)],
    )
    assert (
        len(tx.blob_data.blobs)
        == len(tx.blob_data.versioned_hashes)
        == len(tx.blob_data.proofs)
        == 1
    )
    # assert calculated versioned hash is the same as the provided versioned hash
    assert (
        tx.blob_data.versioned_hashes[0].as_hexstr()
        == ZERO_BLOB_VERSIONED_HASH
    )

    assert (
        tx.blob_data.commitments[0].as_hexstr()
        == ZERO_BLOB_COMMITMENT_AND_PROOF_HASH
    )
    assert (
        tx.blob_data.proofs[0].as_hexstr()
        == ZERO_BLOB_COMMITMENT_AND_PROOF_HASH
    )


def test_sign_blob_transaction_matches_expected_bytes():
    """Test that signed blob transaction matches pre-computed EIP-7594 format bytes."""
    with open(ZERO_BLOB_EIP7594_SIGNED_PATH) as f:
        expected_tx_bytes = to_bytes(hexstr=f.read().strip("\n"))

    signed_tx = TEST_ACCT.sign_transaction(BLOB_TX_DICT, blobs=[ZERO_BLOB])
    assert signed_tx.raw_transaction == HexBytes(expected_tx_bytes)


def test_blob_transaction_calculation_with_nonzero_blob():
    """Test blob transaction with non-zero blob data."""
    with open(BLOB_DATA_1_PATH) as blob_data_1_file:
        blob_data_1 = to_bytes(hexstr=blob_data_1_file.read().strip("\n"))

    tx = BlobTransaction.from_dict(BLOB_TX_DICT, blobs=[blob_data_1])
    assert len(tx.blob_data.blobs) == len(tx.blob_data.versioned_hashes) == 1
    assert (
        len(tx.blob_data.cell_proofs) == 128
    )  # EIP-7594: 128 cell proofs per blob

    assert tx.blob_data.blobs[0].as_bytes() == blob_data_1
    # Versioned hash and commitment are unchanged from EIP-4844
    assert tx.blob_data.versioned_hashes[0].as_hexstr() == (
        "0x018ef96865998238a5e1783b6cafbc1253235d636f15d318f1fb50ef6a5b8f6a"
    )
    assert tx.blob_data.commitments[0].as_hexstr() == (
        "0xb44bafc7381d7ba2072cfbb7091c1fa1fdabcf3999270a551fe54a6741ddebc1bdfbeeabe1b74f5c3935aeedf6b2db84"  # noqa: E501
    )
    # EIP-4844 blob proof (single proof per blob, still computed for compatibility)
    assert tx.blob_data.proofs[0].as_hexstr() == (
        "0x963150f3ee4d5e5f065429f587b4fa199cd8a866b8f6388eb52372870052603c98194c6521077c3260c41bf3b796c833"  # noqa: E501
    )

    # Verify roundtrip works
    signed = TEST_ACCT.sign_transaction(tx.dictionary, blobs=[blob_data_1])
    tx_from_bytes = BlobTransaction.from_bytes(signed.raw_transaction)
    assert tx_from_bytes.blob_data.blobs[0].as_bytes() == blob_data_1
    assert len(tx_from_bytes.blob_data.cell_proofs) == 128


def test_high_and_low_blob_count_limit_validation():
    with pytest.raises(ValidationError, match="must contain at least 1 blob"):
        BlobTransaction.from_dict(BLOB_TX_DICT, blobs=[])

    # make sure up to 6 blobs can be added to a blob transaction
    BlobTransaction.from_dict(
        BLOB_TX_DICT, blobs=[to_bytes(hexstr=ZERO_BLOB)] * 6
    )

    # assert raises if more than 6 blobs
    with pytest.raises(
        ValidationError, match="cannot contain more than 6 blobs"
    ):
        BlobTransaction.from_dict(
            BLOB_TX_DICT, blobs=[to_bytes(hexstr=ZERO_BLOB)] * 7
        )


# --- EIP-7594 PeerDAS Cell Proofs Tests ---


def test_deserialize_legacy_eip4844_transaction():
    """
    Test that old EIP-4844 format transactions can still be deserialized.

    Legacy format: [tx_payload_body, blobs, commitments, proofs]
    New EIP-7594 format: [tx_payload_body, wrapper_version, blobs, commitments, cell_proofs]

    When deserializing legacy format, cell_proofs are recomputed from blobs.
    """
    # This file contains an EIP-4844 format transaction (pre-EIP-7594)
    with open(SIGNED_TX_PATH) as signed_tx_file:
        legacy_tx_bytes = HexBytes(
            to_bytes(hexstr=signed_tx_file.read().strip("\n"))
        )

    tx = BlobTransaction.from_bytes(legacy_tx_bytes)

    assert tx.blob_data is not None
    assert len(tx.blob_data.blobs) == 1
    assert tx.blob_data.blobs[0].as_hexstr() == ZERO_BLOB

    assert len(tx.blob_data.cell_proofs) == 128

    assert (
        tx.blob_data.versioned_hashes[0].as_hexstr()
        == ZERO_BLOB_VERSIONED_HASH
    )
    assert (
        tx.blob_data.commitments[0].as_hexstr()
        == ZERO_BLOB_COMMITMENT_AND_PROOF_HASH
    )


def test_deserialize_legacy_eip4844_transaction_with_nonzero_blob():
    """
    Test deserializing a legacy EIP-4844 transaction with non-zero blob data.

    This tests backward compatibility with real blob data, not just zero blobs.
    """
    with open(BLOB_DATA_1_PATH) as blob_data_file:
        expected_blob = to_bytes(hexstr=blob_data_file.read().strip("\n"))

    with open(BLOB_DATA_1_SIGNED_PATH) as signed_tx_file:
        legacy_tx_bytes = HexBytes(
            to_bytes(hexstr=signed_tx_file.read().strip("\n"))
        )

    tx = BlobTransaction.from_bytes(legacy_tx_bytes)

    assert tx.blob_data is not None
    assert len(tx.blob_data.blobs) == 1
    assert tx.blob_data.blobs[0].as_bytes() == expected_blob

    # EIP-7594: 128 cell proofs per blob (recomputed from blob data)
    assert len(tx.blob_data.cell_proofs) == 128

    # Versioned hash and commitment match expected values for blob_data_1
    assert tx.blob_data.versioned_hashes[0].as_hexstr() == (
        "0x018ef96865998238a5e1783b6cafbc1253235d636f15d318f1fb50ef6a5b8f6a"
    )
    assert tx.blob_data.commitments[0].as_hexstr() == (
        "0xb44bafc7381d7ba2072cfbb7091c1fa1fdabcf3999270a551fe54a6741ddebc1bdfbeeabe1b74f5c3935aeedf6b2db84"  # noqa: E501
    )


def _get_consensus_spec_test_cases():
    """Load valid test cases from consensus-spec-tests."""
    test_cases = []
    pattern = os.path.join(CONSENSUS_SPEC_TESTS_PATH, "*_valid_*", "data.yaml")
    for test_file in glob.glob(pattern):
        test_name = os.path.basename(os.path.dirname(test_file))
        test_cases.append((test_name, test_file))
    return test_cases


@pytest.mark.parametrize(
    "test_name,test_file",
    _get_consensus_spec_test_cases(),
    ids=lambda x: x if isinstance(x, str) and "valid" in x else "",
)
def test_cell_proofs_match_consensus_spec_vectors(test_name, test_file):
    """
    Test that computed cell proofs match ethereum/consensus-spec-tests vectors.

    Test vectors from: https://github.com/ethereum/consensus-spec-tests
    Release: v1.6.0-beta.0
    """
    with open(test_file) as f:
        test_data = yaml.safe_load(f)

    blob_hex = test_data["input"]["blob"]
    blob_bytes = to_bytes(hexstr=blob_hex)

    # Expected outputs from consensus-spec-tests
    expected_cells = test_data["output"][0]
    expected_proofs = test_data["output"][1]

    # Create a transaction with the blob to compute cell proofs
    tx = BlobTransaction.from_dict(BLOB_TX_DICT, blobs=[blob_bytes])

    # Verify we get 128 cell proofs per blob
    assert (
        len(tx.blob_data.cell_proofs) == 128
    ), f"Expected 128 cell proofs, got {len(tx.blob_data.cell_proofs)}"

    # Verify each cell proof matches the expected value
    for i, (computed_proof, expected_proof) in enumerate(
        zip(tx.blob_data.cell_proofs, expected_proofs)
    ):
        assert (
            computed_proof.as_hexstr() == expected_proof.lower()
        ), f"Cell proof {i} mismatch in {test_name}"


def test_cell_proofs_count_with_multiple_blobs():
    blob = to_bytes(hexstr=ZERO_BLOB)

    for num_blobs in [1, 2, 3, 6]:
        tx = BlobTransaction.from_dict(BLOB_TX_DICT, blobs=[blob] * num_blobs)
        expected_proofs = 128 * num_blobs
        assert len(tx.blob_data.cell_proofs) == expected_proofs


def test_blob_transaction_roundtrip_with_cell_proofs():
    """Test signing a blob transaction and deserializing it back."""
    blob = to_bytes(hexstr=ZERO_BLOB)
    tx = BlobTransaction.from_dict(BLOB_TX_DICT, blobs=[blob])

    # Sign the transaction
    signed_tx = TEST_ACCT.sign_transaction(tx.dictionary, blobs=[blob])

    # Deserialize from bytes
    tx_from_bytes = BlobTransaction.from_bytes(signed_tx.raw_transaction)

    # Verify blob data is preserved
    assert tx_from_bytes.blob_data is not None
    assert len(tx_from_bytes.blob_data.blobs) == 1
    assert len(tx_from_bytes.blob_data.versioned_hashes) == 1
    assert len(tx_from_bytes.blob_data.cell_proofs) == 128

    # Verify the blob content matches
    assert tx_from_bytes.blob_data.blobs[0].as_hexstr() == ZERO_BLOB

    # Verify versioned hash matches expected and dictionary value
    assert (
        tx_from_bytes.blob_data.versioned_hashes[0].as_hexbytes()
        == tx_from_bytes.dictionary["blobVersionedHashes"][0]
        == HexBytes(ZERO_BLOB_VERSIONED_HASH)
    )

    # Verify commitment matches
    assert (
        tx_from_bytes.blob_data.commitments[0].as_hexstr()
        == ZERO_BLOB_COMMITMENT_AND_PROOF_HASH
    )

    # Verify cell proofs match between original and deserialized
    for i, (original, deserialized) in enumerate(
        zip(tx.blob_data.cell_proofs, tx_from_bytes.blob_data.cell_proofs)
    ):
        assert original.as_hexstr() == deserialized.as_hexstr()


def _get_go_eth_kzg_test_cases():
    """
    Load test cases combining consensus-spec-tests blobs with go-eth-kzg signed transactions.

    Blobs are sourced from consensus-spec-tests YAML files (authoritative source).
    Signed transaction bytes are from go-eth-kzg JSON (cross-implementation validation).
    """
    # Load go-eth-kzg signed transactions indexed by test name
    with open(GO_ETH_KZG_COMPUTED_PATH) as f:
        go_eth_kzg_data = {item["test_name"]: item for item in json.load(f)}

    test_cases = []
    pattern = os.path.join(CONSENSUS_SPEC_TESTS_PATH, "*_valid_*", "data.yaml")
    for test_file in glob.glob(pattern):
        test_name = os.path.basename(os.path.dirname(test_file))
        if test_name in go_eth_kzg_data:
            # Read blob from consensus-spec-tests YAML
            with open(test_file) as f:
                yaml_data = yaml.safe_load(f)
            test_cases.append(
                (
                    test_name,
                    yaml_data["input"]["blob"],
                    go_eth_kzg_data[test_name]["signed_transaction_hex"],
                )
            )
    return test_cases


@pytest.mark.parametrize(
    "test_name,blob_hex,expected_tx_hex",
    _get_go_eth_kzg_test_cases(),
    ids=lambda x: x if isinstance(x, str) and "valid" in x else "",
)
def test_signed_tx_bytes_match_go_eth_kzg(
    test_name, blob_hex, expected_tx_hex
):
    """
    Test that signed EIP-7594 transaction bytes match go-eth-kzg output exactly.

    This provides byte-for-byte verification between:
    - Python: eth-account using ckzg library
    - Go: go-eth-kzg library (crate-crypto/go-eth-kzg) with manual RLP encoding

    Blobs are sourced from consensus-spec-tests (authoritative).
    Expected transaction bytes are from go-eth-kzg (cross-implementation validation).

    Both implementations produce identical EIP-7594 format transactions:
    0x03 || rlp([tx_payload_body, wrapper_version, blobs, commitments, cell_proofs])
    """
    blob_bytes = to_bytes(hexstr=blob_hex)

    # Sign with eth-account (Python/ckzg)
    signed_tx = TEST_ACCT.sign_transaction(BLOB_TX_DICT, blobs=[blob_bytes])

    # Get go-eth-kzg signed transaction (EIP-7594 format)
    go_tx_bytes = to_bytes(hexstr=expected_tx_hex)

    # Compare raw transaction bytes
    assert signed_tx.raw_transaction == HexBytes(go_tx_bytes), (
        f"Raw transaction bytes mismatch in {test_name}:\n"
        f"  Python len: {len(signed_tx.raw_transaction)}\n"
        f"  Go len: {len(go_tx_bytes)}"
    )
