//! BudZero STARK sınırı: üretim doğruluğunun kriptografik ispatı.
//!
//! Challenge-cevap (`challenge::verify`) ucuzdur ama validatörün üretimi
//! gerçekten yaptığını matematiğe dayamaz: doğrulayıcı tarifi kendisi üretir
//! (aynı maliyet). Tartışmalı/yüksek değerli manifestlerde üretim, BudZero
//! (BudZKVM, Plonky3 STARK) ile ispatlanır: validatör üretim izini çalıştırır,
//! STARK üretir, zincir yalnız STARK'ı doğrular - herkes üretimi yeniden
//! koşmaz. RISC Zero/SP1 deseninin Budlum karşılığı.
//!
//! Bu modül prototip sınırıdır: gerçek BudZero entegrasyonu budzero/ crates'i
//! ile yapılır; burada arayüz + iz (trace) modeli tanımlıdır.

use crate::recipe::Recipe;

/// Bir üretimin STARK ile ispatlanabilir izi.
///
/// Gerçek sistemde bu, BudZero'nun yürütme izidir (354 kolonluk trace deseni).
/// Prototipte iz, üretim adımlarının giriş/çıkış çiftleridir; STARK yerine
/// `deterministic_replay` ile doğrulanır.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderTrace {
    pub recipe: Recipe,
    /// Her adımın (counter, üretilen blok) çifti.
    pub blocks: Vec<(u64, [u8; 32])>,
}

/// Üretim izini yeniden oynatarak doğrular (prototip STARK yerine geçer).
///
/// Gerçekte: `budzero` içinde trace'i STARK'a çevir, zincirde `VerifyMerkle`
/// (64-derinlik) ile doğrula. Prototipte deterministik replay, izin içeriği
/// doğru ürettiğini gösterir.
pub fn deterministic_replay(trace: &RenderTrace) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for (counter, block) in &trace.blocks {
        let expected = crate::recipe::prg_block(&trace.recipe.seed, *counter);
        if expected != *block {
            return Err(format!("trace block {counter} eslesmedi"));
        }
        out.extend_from_slice(block);
    }
    if (out.len() as u32) < trace.recipe.out_len {
        return Err("trace kisa: out_len karsilanmadi".to_string());
    }
    out.truncate(trace.recipe.out_len as usize);
    Ok(out)
}

/// STARK doğrulama maliyeti tahmini (budget fonksiyonu - gerçek ölçüm
/// budzero ile yapılır). Gerçek sistemde bu, `VerifyMerkle` çağrı sayısıdır.
pub fn stark_verification_cost(blocks: usize) -> u64 {
    // Her blok bir iz satırı; Plonky3-STARK doğrulama satır sayısıyla
    // logaritmik yerine yaklaşık doğrusal ölçeklenir (prototip sabiti).
    (blocks as u64).saturating_mul(120)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipe::{render, GeneratorId};

    fn recipe() -> Recipe {
        Recipe {
            generator: GeneratorId::Fractal,
            seed: [3u8; 32],
            step_budget: 1_000,
            out_len: 96,
            version: 1,
            residual: Vec::new(),
        }
    }

    #[test]
    fn replay_uretimle_eslesir() {
        let r = recipe();
        let produced = render(&r).unwrap();
        // izi render'dan kur: tam blok sayisi (ceil), her blok 32 bayt
        let block_count = produced.len().div_ceil(32);
        let blocks: Vec<(u64, [u8; 32])> = (0..block_count as u64)
            .map(|c| {
                let mut b = [0u8; 32];
                let start = (c * 32) as usize;
                let end = (start + 32).min(produced.len());
                b[..end - start].copy_from_slice(&produced[start..end]);
                (c, b)
            })
            .collect();
        let trace = RenderTrace { recipe: r, blocks };
        assert_eq!(deterministic_replay(&trace).unwrap(), produced);
    }

    #[test]
    fn bozuk_trace_reddedilir() {
        let r = recipe();
        let produced = render(&r).unwrap();
        let block_count = produced.len().div_ceil(32);
        let mut blocks: Vec<(u64, [u8; 32])> = (0..block_count as u64)
            .map(|c| {
                let mut b = [0u8; 32];
                let start = (c * 32) as usize;
                let end = (start + 32).min(produced.len());
                b[..end - start].copy_from_slice(&produced[start..end]);
                (c, b)
            })
            .collect();
        blocks[0].1[0] ^= 0xFF; // izi boz
        let trace = RenderTrace { recipe: r, blocks };
        assert!(deterministic_replay(&trace).is_err());
    }
}
