//! PoRGen - Proof of Regeneration (BUD Üretim-Ağı prototipi).
//!
//! Depolamayı neredeyse 0'a çeker, maliyeti CPU'ya kaydırır: içerik baytı
//! zincirde durmaz; tarif + commitment durur, baytlar talep anında
//! deterministik üretimle doğar. Bu crate, 7f'deki icadın çalışan
//! çekirdeğidir (testli, kayan noktasız).
//!
//! Modüller:
//! - `recipe`: üretim tarifi + deterministik render + commitment.
//! - `challenge`: PoRGen challenge (üret-ispatla; cevapsız = slash).
//! - `queue`: KTT-bağlı üretim kuyruğu (çapraz-domain ağırlıklı).
//! - `stark`: BudZero STARK sınırı (prototip: deterministik replay).
//! - `radical`: "temel + fark" radikal yaklaşımının dürüst ölçümü.
//!
//! # Prototip clippy istisnaları (gerekçeli)
//!
//! Bu crate Tier 1 prototiptir (ana repo CI gate'i değildir; `kanit_ekonomisi`
//! ile aynı statüde). Pedantic kuralların bir kısmı prototip geliştirme
//! hızı için bilinçli olarak esnetildi; ana repoya taşınırken sıkılaştırılır:
//! - `doc_markdown`: doc yorumlarındaki kod referanslarına backtick ekleme
//!   disiplini; prototipte gürültü, anlam kaybı yok.
//! - `must_use_candidate`: saf fonksiyonlar `#[must_use]` ile işaretlenmemiş;
//!   prototip API'si tüketiciye dönük değil.
//! - `missing_errors_doc`: `Result` dönen fonksiyonlarda `# Errors` bölümü
//!   yok; prototip iç belgeliğidir.
//! - `cast_possible_truncation` / `cast_precision_loss` / `cast_sign_loss`:
//!   boyut dönüşümleri bilinçli (out_len u32, blok 32 bayt, oran f64);
//!   değer aralıkları testle sabit.

#![allow(
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

pub mod challenge;
pub mod queue;
pub mod radical;
pub mod recipe;
pub mod stark;
