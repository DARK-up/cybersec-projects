#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent verification of the OpenSSL libcrypto AES-256-GCM fallback path
used when Python `cryptography` is absent, plus Vault key rotation compatibility.
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "dark"))

import enterprise_db as edb
import security_hardening as sh


def test_openssl_libcrypto_aes_gcm_roundtrip_tamper_nonces_and_aad(monkeypatch):
    monkeypatch.setattr(sh, "CRYPTOGRAPHY_AESGCM_OK", False)
    monkeypatch.setattr(sh, "_CryptAESGCM", None)

    key = secrets.token_bytes(32)
    pt = b"DARK-SECRET-TOKEN-998877665544332211"
    aad = b"tenant:acme:vault"

    n1, ct1, tag1 = sh.aes_gcm_encrypt(key, pt, aad=aad)
    n2, ct2, tag2 = sh.aes_gcm_encrypt(key, pt, aad=aad)

    assert len(n1) == 12 and len(n2) == 12
    assert n1 != n2
    assert ct1 != ct2

    dec = sh.aes_gcm_decrypt(key, n1, ct1, tag1, aad=aad)
    assert dec == pt

    bad_tag = bytes([tag1[0] ^ 0x01]) + tag1[1:]
    with pytest.raises(Exception):
        sh.aes_gcm_decrypt(key, n1, ct1, bad_tag, aad=aad)

    bad_ct = bytes([ct1[0] ^ 0x80]) + ct1[1:]
    with pytest.raises(Exception):
        sh.aes_gcm_decrypt(key, n1, bad_ct, tag1, aad=aad)

    with pytest.raises(Exception):
        sh.aes_gcm_decrypt(key, n1, ct1, tag1, aad=b"tenant:evil:vault")

    with pytest.raises(Exception):
        sh.aes_gcm_decrypt(secrets.token_bytes(32), n1, ct1, tag1, aad=aad)


def test_vault_key_rotation_preserves_backward_compatibility(monkeypatch):
    monkeypatch.setattr(sh, "CRYPTOGRAPHY_AESGCM_OK", False)
    monkeypatch.setattr(sh, "_CryptAESGCM", None)

    tok = edb.set_current_actor("secadmin", "admin", "127.0.0.1", tenant_id="default")
    try:
        rec = edb.store_vault_secret("openssl-rot-secret", "api_token", "bearer_old_v1_9911")
        assert rec["alg"] == "AES-256-GCM"
        assert edb.reveal_vault_secret(rec["id"]) == "bearer_old_v1_9911"

        cur_ver, _ = edb._get_vault_key_versioned()
        nb, cb, mb = edb._encrypt_secret("legacy-compat-secret", aad_context="vault:default")

        rot = edb.rotate_vault_keys()
        assert rot["reencrypted"] >= 1 and rot["current_version"] > cur_ver
        assert edb.reveal_vault_secret(rec["id"]) == "bearer_old_v1_9911"
        assert edb._decrypt_secret(
            nb, cb, mb, key_version=cur_ver, alg="AES-256-GCM", aad_context="vault:default"
        ) == "legacy-compat-secret"
    finally:
        edb.reset_current_actor(tok)
