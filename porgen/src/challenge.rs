//! PoRGen challenge: validatörden üretim ispatı ister.
//!
//! Validatör, zincirde yalnız tarifi duran bir manifest'i CPU ile üretir ve
//! çıktının commitment'ını getirir. Doğrulama = getirilen commitment ile
//! tarifin ürettiği baytların hash'i eşleşmeli (deterministik üretim
//! sayesinde herkes aynı sonucu alır). Cevapsız veya bozuk cevap = slash.
//!
//! İki doğrulama katmanı:
//! 1. `verify` - ucuz, herkes çalıştırır (challenge-cevap deseni).
//! 2. `StarkBoundary` - BudZero STARK ile üretimin tam doğruluğu (ağır,
//!    tartışmalı cevaplarda veya yüksek değerli manifestlerde).

use crate::recipe::{content_hash, render, Recipe, RenderError};

/// Challenge sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeOutcome {
    /// Cevap doğru: üretim commitment'ı eşleşti.
    Accepted,
    /// Cevap geldi ama commitment yanlış (üretim bozuk ya da yalan).
    Rejected,
    /// Cevap süresi doldu: slash.
    Missed,
}

/// PoRGen challenge kaydı.
#[derive(Debug, Clone)]
pub struct PoRGenChallenge {
    pub manifest_id: [u8; 32],
    pub recipe: Recipe,
    pub deadline_epoch: u64,
}

/// Bir challenge'ın cevabını doğrular.
///
/// `submitted` = validatörün ürettiğini iddia ettiği baytların commitment'ı.
/// Doğrulama: tarifi yerel olarak üret, hash'le, iddia ile karşılaştır.
/// `render` deterministik olduğu için eşleşme, validatörün gerçekten ürettiğini
/// gösterir (aynı tarif aynı çıktıyı verir).
pub fn verify(
    challenge: &PoRGenChallenge,
    submitted: &[u8; 32],
) -> Result<ChallengeOutcome, RenderError> {
    let produced = render(&challenge.recipe)?;
    let expected = content_hash(&produced);
    Ok(if expected == *submitted {
        ChallengeOutcome::Accepted
    } else {
        ChallengeOutcome::Rejected
    })
}

/// Epoch eşiği: `current_epoch` deadline'ı aştıysa cevap artık kabul edilmez.
pub fn settle(
    challenge: &PoRGenChallenge,
    current_epoch: u64,
    submitted: Option<&[u8; 32]>,
) -> ChallengeOutcome {
    if current_epoch > challenge.deadline_epoch {
        return ChallengeOutcome::Missed;
    }
    match submitted {
        None => ChallengeOutcome::Missed,
        Some(bytes) => match verify(challenge, bytes) {
            Ok(ChallengeOutcome::Accepted) => ChallengeOutcome::Accepted,
            _ => ChallengeOutcome::Rejected,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipe::GeneratorId;

    fn challenge() -> PoRGenChallenge {
        PoRGenChallenge {
            manifest_id: [1u8; 32],
            recipe: Recipe {
                generator: GeneratorId::Fractal,
                seed: [9u8; 32],
                step_budget: 1_000,
                out_len: 128,
                version: 1,
                residual: Vec::new(),
            },
            deadline_epoch: 100,
        }
    }

    #[test]
    fn dogru_cevap_kabul() {
        let c = challenge();
        let produced = render(&c.recipe).unwrap();
        let hash = content_hash(&produced);
        assert_eq!(verify(&c, &hash).unwrap(), ChallengeOutcome::Accepted);
    }

    #[test]
    fn yanlis_cevap_red() {
        let c = challenge();
        assert_eq!(verify(&c, &[0u8; 32]).unwrap(), ChallengeOutcome::Rejected);
    }

    #[test]
    fn deadline_sonrasi_missed() {
        let c = challenge();
        let produced = render(&c.recipe).unwrap();
        let hash = content_hash(&produced);
        // deadline 100, simdi 101 -> dogru cevap bile gec kaldi
        assert_eq!(settle(&c, 101, Some(&hash)), ChallengeOutcome::Missed);
    }

    #[test]
    fn cevapsiz_slash() {
        let c = challenge();
        assert_eq!(settle(&c, 50, None), ChallengeOutcome::Missed);
    }

    #[test]
    fn deadline_icinde_dogru_cevap_kabul() {
        let c = challenge();
        let produced = render(&c.recipe).unwrap();
        let hash = content_hash(&produced);
        assert_eq!(settle(&c, 99, Some(&hash)), ChallengeOutcome::Accepted);
    }
}
