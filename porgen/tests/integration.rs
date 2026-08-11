//! Uçtan uca PoRGen akışı: yükleme -> tarif -> üretim kuyruğu -> challenge ->
//! doğrulama -> slash. Kullanıcının Şart 2'sinin (CPU self-production)
//! kapalı devresini test eder.

// Prototip testleri icin pedantic esnetmesi (bkz. src/lib.rs gerekcesi).
#![allow(
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use porgen::challenge::{settle, ChallengeOutcome, PoRGenChallenge};
use porgen::queue::{order, plan_signature, FinalityWeight, QueueEntry};
use porgen::radical::{classify, RadicalClass};
use porgen::recipe::{content_hash, render, GeneratorId, Recipe};

fn recipe() -> Recipe {
    Recipe {
        generator: GeneratorId::Identicon,
        seed: [42u8; 32],
        step_budget: 10_000,
        out_len: 1024,
        version: 1,
        residual: Vec::new(),
    }
}

#[test]
fn yukle_uret_challenge_dogrula() {
    // 1) İçerik zincire tarif olarak yazılır (bayt yok, tarif var).
    let r = recipe();
    let manifest_id = r.content_id();

    // 2) Bir validatör tarifi CPU ile üretir, commitment'ı yayınlar.
    let produced = render(&r).expect("üretim bütçe içinde");
    let submitted = content_hash(&produced);

    // 3) Challenge: "bu manifest'i üret ve kanıtla".
    let challenge = PoRGenChallenge {
        manifest_id,
        recipe: r,
        deadline_epoch: 500,
    };
    // 4) Doğrulama: tarif yeniden üretilir, hash eşleşir.
    assert_eq!(
        settle(&challenge, 499, Some(&submitted)),
        ChallengeOutcome::Accepted
    );
}

#[test]
fn uretim_kuyrugu_dogru_siralar_ve_imzalar() {
    let mut es = Vec::new();
    for i in 0..8u8 {
        let r = Recipe {
            generator: GeneratorId::Fractal,
            seed: [i; 32],
            step_budget: 5_000,
            out_len: 512,
            version: 1,
            residual: Vec::new(),
        };
        es.push(QueueEntry {
            manifest_id: r.content_id(),
            last_read_epoch: 0,
            read_count: u64::from(i) * 100,
            age_epochs: u64::from(20 - i),
            cost_steps: 500,
            domain_weight: FinalityWeight(100u32 + u32::from(i) * 100),
        });
    }
    let ordered = order(&es);
    // Daha yüksek okuma/domain -> daha önce
    assert!(ordered[0].read_count >= ordered.last().map_or(0, |e| e.read_count));
    let sig = plan_signature(&ordered);
    let sig2 = plan_signature(&order(&es));
    assert_eq!(sig, sig2, "plan imzası deterministik");
}

#[test]
fn radikal_siniflandirma_uretim_kararini_verir() {
    // Yapısal içerik -> Regenerable -> ağda 0 bayt
    let seed = [7u8; 32];
    let structural: Vec<u8> = (0..512u32)
        .flat_map(|c| porgen::recipe::prg_block(&seed, u64::from(c)))
        .take(512)
        .collect();
    assert_eq!(classify(&structural, &seed), RadicalClass::Regenerable);

    // Gürültü -> Organic -> sahipte kalır
    let noise: Vec<u8> = (0..512u16)
        .map(|i| (i.wrapping_mul(7) % 256) as u8)
        .collect();
    assert_eq!(classify(&noise, &seed), RadicalClass::Organic);
}

#[test]
fn cevapsiz_challenge_slash_eder() {
    let r = recipe();
    let challenge = PoRGenChallenge {
        manifest_id: r.content_id(),
        recipe: r,
        deadline_epoch: 100,
    };
    assert_eq!(settle(&challenge, 101, None), ChallengeOutcome::Missed);
}
