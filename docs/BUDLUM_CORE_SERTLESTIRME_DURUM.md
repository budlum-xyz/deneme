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

## ✅ Merge edilen turlar

### Tur 1 - PR #166 (dal `sertles-budlum-core-1`) - MERGED (squash, `9a42e30`)

| # | Sertleştirme | Bulgu kaynağı | Commit |
|---|---|---|---|
| 1 | ed25519 `verify_strict()` (weak-key forgery) - `src/crypto/primitives.rs`, `src/chain/snapshot.rs` | #44 | `18acd12` |
| 2 | libp2p `connection_limits::Behaviour` (OOM/eclipse DoS) - `src/network/node.rs` | #3, #41 | `18acd12` |
| 3 | RPC `max_request_body_size` 50MB→16MB (batch amplification) - `src/rpc/server.rs` | #16, #28 | `18acd12` |
| 4 | request/response `with_request_timeout(30s)` (slowloris) - `src/network/node.rs` | #58, #60 | `d10f332` |
| 5 | clippy-extra uyarı kapatma (pedantic/nursery) - snapshot.rs, node.rs | CI | `5e663eb` |
| 6 | rustfmt uyumu - node.rs connection_limits formatı | CI | `191495a` |

### Tur 2 - PR #170 (dal `sertles-budlum-core-2`) - MERGED (squash, `cca6a80`)

| # | Sertleştirme | Bulgu kaynağı | Commit |
|---|---|---|---|
| 7 | libp2p-yamux `max_num_streams` 512→256 - `src/network/node.rs` | #104 | `7e1093b` |
| 8 | jsonrpsee `BatchRequestConfig::Limit(100)` - `src/rpc/server.rs` | #42 | `7e1093b` |

**Not (Tur 2):** libp2p-yamux 0.48 wrapper'ı iç yamux `max_connection_receive_window`
API'sini expose etmiyor; stream cap bugün uygulanabilen muxer seviyesi sinirdir (#108 takipte).

### Tur 3 - PR #171 (dal `sertles-budlum-core-3`) - MERGED (squash, `fc333ea`)

| # | Sertleştirme | Bulgu kaynağı | Commit |
|---|---|---|---|
| 9 | Release profili: `lto = true` + `codegen-units = 1` + `strip = true` - `Cargo.toml`, `budzero/Cargo.toml` | #196 | `4192ef2` |

## ✅ TAMAMLANDI (2026-08-11)

- **Tur 1** (PR #166): weak-key imza, connection budget, RPC body cap, request timeout
- **Tur 2** (PR #170): yamux stream limiti, RPC batch cap
- **Tur 3** (PR #171): release profili LTO + strip
- Her turda: 35/35 required check success, 0 FAIL, Strix "No security issues found",
  squash merge, dal silindi; GitHub'da 0 açık PR, yalnızca `main`

## 🟢 CI durumu (son kontrol: 2026-08-11)

- Tur 1: 66 check'ten **62 success, 0 FAIL**, 35/35 required success (Miri dahil)
- Tur 2: **35/35 required success, 0 FAIL**; tek in_progress: Kani yavaş set (required değil)
- Tur 3: **35/35 required success, 0 FAIL** (Genesis Reproducibility + Miri dahil - LTO
  davranış paritesi doğrulandı)
- **Strix (her üç turda): "No security issues found."**

## 📋 Karar

- Kullanıcı kararı: **"once_ci"** → CI + Strix yeşil olunca squash merge (uygulandı).
- **"Dur"** - üç tur sertleştirme + 200/200 araştırma tamam; çalışma kapatıldı.

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
