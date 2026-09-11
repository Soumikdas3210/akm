"""Week 1 tests. Run with:  python -m pytest -v"""
import hashlib
import sqlite3

import pytest
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

from akm import corpus
from akm.config import RunConfig, derive_bytes
from akm.provision import (commitment, decrypt_record, provision, unwrap,
                           wrap)
from akm.receipts import RECEIPT_SIZE, Receipt
from akm.schemas import SCORES_COLUMNS, append_row
from akm.store import EPOCH_OLD, Store


# ---------- config / DRBG ----------------------------------------------------
def test_drbg_is_deterministic_and_label_separated():
    assert derive_bytes(1, "dek", 0, 32) == derive_bytes(1, "dek", 0, 32)
    assert derive_bytes(1, "dek", 0, 32) != derive_bytes(2, "dek", 0, 32)   # seed matters
    assert derive_bytes(1, "dek", 0, 32) != derive_bytes(1, "nonce", 0, 32)  # label matters
    assert derive_bytes(1, "dek", 0, 32) != derive_bytes(1, "dek", 1, 32)   # index matters


def test_config_validation_and_roundtrip(tmp_path):
    with pytest.raises(ValueError):
        RunConfig(seed=1, N=10, size=300)      # 300 is not a valid size
    with pytest.raises(ValueError):
        RunConfig(seed=1, N=10, size=200, tau=100)
    cfg = RunConfig(seed=7, N=10, size=200, tau=96)
    cfg.save(tmp_path / "c.json")
    assert RunConfig.load(tmp_path / "c.json") == cfg
    assert cfg.run_id == "s7-N10-b200-t96"


# ---------- corpus -----------------------------------------------------------
@pytest.mark.parametrize("size", [200, 2048, 32768])
def test_records_have_exact_size(size):
    for i in range(20):
        assert len(corpus.make_record(3, i, size)) == size


# ---------- provisioning: the Week-1 "done when" -----------------------------
@pytest.fixture(scope="module")
def run_200(tmp_path_factory):
    out = tmp_path_factory.mktemp("run")
    cfg = RunConfig(seed=1, N=1000, size=200, tau=128)
    summary = provision(cfg, out)
    return cfg, out, summary


def test_n1000_provisions(run_200):
    cfg, out, _ = run_200
    s = Store(out / "store", readonly=True)
    assert s.count() == 1000
    s.close()


def test_tuple_is_285_bytes_at_200B(run_200):
    """Execution Plan §2.2 Week 1 criterion: tuple is 285 B at 200 B payload (+ tau/8)."""
    _, _, summary = run_200
    b = summary["bytes_per_record"]
    assert b["id"] == 16
    assert b["ct"] == 200 + 16          # GCM adds a 16-byte tag
    assert b["nonce"] == 12
    assert b["w_old"] == 40             # AES-KW of a 32-byte key
    assert b["tuple_without_cmt"] == 285
    assert b["cmt"] == 128 / 8
    assert b["tuple_with_cmt"] == 285 + 16


@pytest.mark.parametrize("tau", [64, 96, 128, 256])
def test_commitment_length_is_tau_over_8(tmp_path, tau):
    cfg = RunConfig(seed=2, N=20, size=200, tau=tau)
    s = provision(cfg, tmp_path)
    assert s["bytes_per_record"]["cmt"] == tau / 8


def test_every_record_decrypts_and_commitment_verifies(run_200):
    """Plays V3 for the honest case: unwrap -> decrypt -> equals plaintext; cmt matches."""
    cfg, out, _ = run_200
    k_old = (out / "keys" / "kek_old.bin").read_bytes()
    s = Store(out / "store", readonly=True)
    pt = sqlite3.connect(f"file:{out / 'corpus.db'}?mode=ro", uri=True)
    for rid, body in pt.execute("SELECT id, body FROM plaintext"):
        nonce, ct = s.get_payload(rid)
        w_old, w_new, cmt, epoch = s.get_wrap(rid)
        assert w_new is None and epoch == EPOCH_OLD
        dek = unwrap(k_old, w_old)
        assert decrypt_record(dek, nonce, ct, rid) == body
        assert commitment(dek, rid, cfg.tau) == cmt
    s.close()


def test_provisioning_is_reproducible(tmp_path):
    """Same (seed, N, size, tau) -> byte-identical store contents."""
    cfg = RunConfig(seed=5, N=50, size=200, tau=96)
    provision(cfg, tmp_path / "a")
    provision(cfg, tmp_path / "b")

    def dump(d):
        s = Store(d / "store", readonly=True)
        rows = list(s.payload.execute("SELECT * FROM payload ORDER BY id"))
        rows += list(s.wraps.execute("SELECT * FROM wraps ORDER BY id"))
        s.close()
        return hashlib.sha256(repr(rows).encode()).hexdigest()

    assert dump(tmp_path / "a") == dump(tmp_path / "b")


# ---------- crypto sanity: why F5b (garbage wrap) is the EASY case -----------
def test_wrong_kek_or_garbage_fails_unwrap():
    kek = derive_bytes(9, "k", 0, 32)
    other = derive_bytes(9, "k", 1, 32)
    w = wrap(kek, derive_bytes(9, "d", 0, 32))
    with pytest.raises(InvalidUnwrap):
        unwrap(other, w)                       # wrong master key
    with pytest.raises(InvalidUnwrap):
        unwrap(kek, derive_bytes(9, "g", 0, 40))   # 40 random bytes


def test_commitment_binds_id():
    dek = derive_bytes(1, "d", 0, 32)
    a, b = derive_bytes(1, "id", 0, 16), derive_bytes(1, "id", 1, 16)
    assert commitment(dek, a, 128) != commitment(dek, b, 128)   # swap -> mismatch


# ---------- receipt format ---------------------------------------------------
def test_receipt_roundtrip_and_tamper_detection():
    rid = derive_bytes(1, "id", 0, 16)
    w_old, w_new = b"\x01" * 40, b"\x02" * 40
    ct = b"\x03" * 216
    r = Receipt.build(rid, w_old, w_new, ct, epoch=1)
    blob = r.encode()
    assert len(blob) == RECEIPT_SIZE == 83
    r2 = Receipt.decode(blob)
    assert r2 == r
    assert r2.matches(w_new, ct)
    flipped = bytes([ct[0] ^ 1]) + ct[1:]           # a one-bit flip in C (F3)
    assert not r2.matches(w_new, flipped)


# ---------- CSV contract -----------------------------------------------------
def test_csv_rejects_bad_rows(tmp_path):
    row = {c: 0 for c in SCORES_COLUMNS}
    append_row(tmp_path / "scores.csv", SCORES_COLUMNS, row)
    with pytest.raises(ValueError):
        append_row(tmp_path / "scores.csv", SCORES_COLUMNS, {**row, "typo": 1})
