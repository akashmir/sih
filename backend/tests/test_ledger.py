"""
Blockchain integrity tests — hash chain tamper detection.
"""
import pytest
import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.ledger.blockchain import HashChainLedger, LedgerBlock


@pytest.fixture
def ledger():
    """Create a temporary ledger for each test."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    led = HashChainLedger(db_path)
    yield led
    led.close()
    os.unlink(db_path)


def test_empty_chain_is_valid(ledger):
    """Empty chain should validate as valid."""
    result = ledger.validate_chain()
    assert result["valid"] is True
    assert result["blocks_checked"] == 0


def test_add_single_block(ledger):
    """Adding a block increases chain length."""
    block = ledger.add_block(
        watermark_id="wm123",
        recipient_id="user1",
        document_hash="hash123",
        signature="sig123",
        sig_algorithm="ML-DSA-65",
    )
    assert block.block_index == 0
    assert ledger.get_chain_length() == 1
    assert len(block.block_hash) == 64  # SHA-256 hex


def test_add_multiple_blocks(ledger):
    """Adding multiple blocks creates proper chain."""
    blocks = []
    for i in range(5):
        block = ledger.add_block(
            watermark_id=f"wm{i}",
            recipient_id=f"user{i}",
            document_hash=f"hash{i}",
            signature=f"sig{i}",
            sig_algorithm="ML-DSA-65",
        )
        blocks.append(block)

    assert ledger.get_chain_length() == 5
    # Check chain linkage
    for i in range(1, 5):
        assert blocks[i].prev_hash == blocks[i-1].block_hash


def test_chain_validation_valid(ledger):
    """Chain with multiple blocks should validate."""
    for i in range(10):
        ledger.add_block(
            watermark_id=f"wm{i}",
            recipient_id=f"user{i}",
            document_hash=f"hash{i}",
            signature=f"sig{i}",
            sig_algorithm="ML-DSA-65",
        )

    result = ledger.validate_chain()
    assert result["valid"] is True
    assert result["blocks_checked"] == 10
    assert len(result["errors"]) == 0


def test_tamper_detection_data_modification(ledger):
    """Modifying block data should be detected."""
    for i in range(5):
        ledger.add_block(
            watermark_id=f"wm{i}",
            recipient_id=f"user{i}",
            document_hash=f"hash{i}",
            signature=f"sig{i}",
            sig_algorithm="ML-DSA-65",
        )

    # Tamper with a block's data directly in the database
    ledger.conn.execute(
        "UPDATE blocks SET watermark_id = 'tampered' WHERE block_index = 2"
    )
    ledger.conn.commit()

    result = ledger.validate_chain()
    assert result["valid"] is False
    assert result["blocks_checked"] == 5
    assert len(result["errors"]) > 0


def test_tamper_detection_hash_modification(ledger):
    """Modifying block hash should be detected."""
    for i in range(5):
        ledger.add_block(
            watermark_id=f"wm{i}",
            recipient_id=f"user{i}",
            document_hash=f"hash{i}",
            signature=f"sig{i}",
            sig_algorithm="ML-DSA-65",
        )

    # Tamper with a block's hash
    ledger.conn.execute(
        "UPDATE blocks SET block_hash = '0000000000000000000000000000000000000000000000000000000000000000' WHERE block_index = 3"
    )
    ledger.conn.commit()

    result = ledger.validate_chain()
    assert result["valid"] is False


def test_tamper_detection_prev_hash_modification(ledger):
    """Modifying prev_hash linkage should be detected."""
    for i in range(5):
        ledger.add_block(
            watermark_id=f"wm{i}",
            recipient_id=f"user{i}",
            document_hash=f"hash{i}",
            signature=f"sig{i}",
            sig_algorithm="ML-DSA-65",
        )

    # Break the chain by modifying prev_hash
    ledger.conn.execute(
        "UPDATE blocks SET prev_hash = 'broken' WHERE block_index = 2"
    )
    ledger.conn.commit()

    result = ledger.validate_chain()
    assert result["valid"] is False


def test_find_by_watermark(ledger):
    """Find block by watermark ID."""
    for i in range(5):
        ledger.add_block(
            watermark_id=f"wm{i}",
            recipient_id=f"user{i}",
            document_hash=f"hash{i}",
            signature=f"sig{i}",
            sig_algorithm="ML-DSA-65",
        )

    block = ledger.find_by_watermark("wm2")
    assert block is not None
    assert block.watermark_id == "wm2"
    assert block.recipient_id == "user2"


def test_find_by_recipient(ledger):
    """Find all blocks for a recipient."""
    for i in range(5):
        ledger.add_block(
            watermark_id=f"wm{i}",
            recipient_id="user1" if i % 2 == 0 else "user2",
            document_hash=f"hash{i}",
            signature=f"sig{i}",
            sig_algorithm="ML-DSA-65",
        )

    blocks = ledger.find_by_recipient("user1")
    assert len(blocks) == 3
    for b in blocks:
        assert b.recipient_id == "user1"


def test_get_all_blocks_pagination(ledger):
    """Get blocks with pagination."""
    for i in range(10):
        ledger.add_block(
            watermark_id=f"wm{i}",
            recipient_id=f"user{i}",
            document_hash=f"hash{i}",
            signature=f"sig{i}",
            sig_algorithm="ML-DSA-65",
        )

    # Get first 5
    blocks = ledger.get_all_blocks(limit=5, offset=0)
    assert len(blocks) == 5

    # Get next 5
    blocks = ledger.get_all_blocks(limit=5, offset=5)
    assert len(blocks) == 5


def test_genesis_block_prev_hash(ledger):
    """First block should have prev_hash of all zeros."""
    block = ledger.add_block(
        watermark_id="wm0",
        recipient_id="user0",
        document_hash="hash0",
        signature="sig0",
        sig_algorithm="ML-DSA-65",
    )
    assert block.prev_hash == "0" * 64
