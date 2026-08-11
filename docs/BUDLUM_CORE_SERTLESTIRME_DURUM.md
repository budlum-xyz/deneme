# Budlum Core Sertleştirme - Durum Raporu (2026-08-11)

> Bu dosya, Budlum Core sertleştirme çalışmasının canlı durum kaydıdır.
> Web araştırma günlüğü: `docs/BUDLUM_CORE_SERTLESTIRME_ARASTIRMA.md` (200/200 sorgu).

## ✅ 200/200 web araştırması TAMAMLANDI

**Günlük:** `docs/BUDLUM_CORE_SERTLESTIRME_ARASTIRMA.md` (296 satır, 200 sorgu; her satırda bulgu + kaynak URL).

**Kapsanan alanlar:** PoS/slashing, long-range attack, libp2p eclipse/DoS, fixed-point aritmetik,
replay/chain-id, timing attack, signature malleability, deserialization bomb, Merkle/erasure,
supply-chain (cargo-audit/deps/typosquatting/build.rs), BFT finality, zkVM soundness, TEE
attestation, RPC rate-limit/batch/auth, determinizm (HashMap/SystemTime), fee market,
wallet key mgmt, bridge/gov/oracle, BLS-PoP, PQC, reproducible builds, panic/abort,
tokio cancel-safety/starvation, gas metering, state bloat, checkpoint-sync, peer scoring,
validator key HSM/remote-signer, cold storage, slashing protection DB, NTP skew, MEV,
censorship resistance, async supervisor, DB key prefix encoding, stateful fuzzing...

## 🔧 Kod sertleştirmeleri → PR #166 (dal `sertles-budlum-core-1`)

| # | Sertleştirme | Bulgu kaynağı | Commit |
|---|---|---|---|
| 1 | ed25519 `verify_strict()` (weak-key forgery) - `src/crypto/primitives.rs`, `src/chain/snapshot.rs` | #44 | `18acd12` |
| 2 | libp2p `connection_limits::Behaviour` (OOM/eclipse DoS) - `src/network/node.rs` | #3, #41 | `18acd12` |
| 3 | RPC `max_request_body_size` 50MB→16MB (batch amplification) - `src/rpc/server.rs` | #16, #28 | `18acd12` |
| 4 | request/response `with_request_timeout(30s)` (slowloris) - `src/network/node.rs` | #58, #60 | `d10f332` |
| 5 | clippy-extra uyarı kapatma (pedantic/nursery yeni uyarılar) - snapshot.rs, node.rs | CI | `5e663eb` |
| 6 | rustfmt uyumu - node.rs connection_limits formatı | CI | `191495a` |

**Head:** `191495a2eccd06d59d799fc806d81329b51d8174`

## 🟢 CI durumu (son kontrol: 2026-08-11)

- 66 check'ten **62 success, 0 FAIL**
- **Budlum Core: success** ✓ (önceki FAIL'ler clippy-extra + rustfmt idi; `191495a` ile kapandı)
- **Strix Security Review: "No security issues found."** (d10f332 için; son 2 commit yalnızca
  clippy-allow + rustfmt, davranışsal değişiklik içermiyor)
- Hâlâ `in_progress` (required DEĞİL): Fuzz Quick (60s × 9), AddressSanitizer, Kani yavaş set
- Hâlâ `in_progress` (**required**): Miri UB Denetimi → `mergeable_state: blocked` sebebi
- Required 35 check'in 34'ü success; tek eksik Miri

## 📋 Karar ve sıradaki adım

- Kullanıcı kararı: **"once_ci"** → CI (35 required check) + Strix yeşil olunca **squash merge**.
- Miri UB Denetimi tamamlanınca: PR #166 squash merge → dal `sertles-budlum-core-1` silinecek.
- Bu dokümantasyon PR'ı (docs/) PR #166'nın CI'ını resetlememek için ayrı tutuldu.

## ✅ Araştırmada "zaten sağlam" doğrulananlar (kod değişikliği gerekmedi)

- `overflow-checks=true` + `panic=abort` release profili
- Mempool: imza öncelikli, min_fee, max_size, eviction, per-sender cap, RBF bump (u128/ceil)
- Block size limit + protobuf 10MB cap + gossip Strict validation
- Timestamp doğrulama (drift + monotonic + interval)
- Tx: chain_id + nonce + signature_version + canonical genesis
- BLS PoP (RFC9380) + chain_id/adres bağlama
- Gossip peer scoring (behaviour penalty + IP collocation 4)
- Erasure reconstruction ContentId doğrulama, storage checksum, log redaction
- RPC auth + per-IP rate limit + origin kontrol
