//! PoRGen çekirdeği: üretim tarifi (recipe) ve deterministik üretim.
//!
//! Bir içerik ya zincirde tarif olarak durur (tohum + adım bütçesi + sürüm +
//! rezidüel) ya da sahip cihazında (organik). Bu modül tarifin üretimini
//! gerçekleştirir: aynı tarif, aynı çıktıyı üretir (determinizm şartı).
//!
//! Üretim maliyeti adım bütçesiyle sınırlıdır (DoS koruması; mevcut
//! `step_budget` deseniyle aynı). Kayan nokta yok: tüm üretim tamsayı
//! aritmetiği + SHA-256 tabanlı PRG ile yapılır (Budlum kuralı).

use sha2::{Digest, Sha256};

/// Üretici kimliği: hangi deterministik üretecin çalıştırılacağı.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GeneratorId {
    /// Kimlik görseli (identicon): tohumdan simetrik ızgara.
    Identicon,
    /// Fraktal: tohumdan deterministik gürültü haritası.
    Fractal,
    /// Sözlük metni: tohumdan deterministik kelime dizisi.
    Lexicon,
}

/// Üretim tarifi: zincirde duran her şey.
///
/// Boyut: 32 (seed) + 4 (step_budget) + 4 (out_len) + 1 (version) + 1
/// (generator) + rezidüel. Organik içerikte rezidüel, temel üretimle
/// bit-birebir eşleşmeyen farkı taşır (radikal yaklaşımın dürüst sınırı).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipe {
    pub generator: GeneratorId,
    pub seed: [u8; 32],
    /// Adım bütçesi: üretim bu kadar işlemi aşamaz (DoS koruması).
    pub step_budget: u32,
    /// Beklenen çıktı uzunluğu (bayt). Üretici bunu üretmek zorundadır.
    pub out_len: u32,
    /// Üretici sürümü: tarif ile üreteç aynı sürümde olmalı (determinizm).
    pub version: u32,
    /// Rezidüel: temel üretimle hedef arasındaki fark (boş olabilir).
    pub residual: Vec<u8>,
}

impl Recipe {
    /// Tarifin zincir kimliği: içeriğin `manifest_id` karşılığı.
    pub fn content_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"BUD_PORGEN_V1");
        h.update([self.generator as u8]);
        h.update(self.seed);
        h.update(self.step_budget.to_le_bytes());
        h.update(self.out_len.to_le_bytes());
        h.update(self.version.to_le_bytes());
        h.update(&self.residual);
        h.finalize().into()
    }
}

/// Deterministik PRG: tohum + sayaçtan bayt bloğu üretir.
///
/// Kayan nokta yok, dış girdi yok: aynı (seed, counter) her zaman aynı
/// bloğu verir. Adım sayacı, `step_budget`'ı aşan üretimi durdurur.
/// `stark.rs` trace replay'i de bu fonksiyonu kullanır (public).
pub fn prg_block(seed: &[u8; 32], counter: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"BUD_PORGEN_PRG");
    h.update(seed);
    h.update(counter.to_le_bytes());
    h.finalize().into()
}

/// Çıktı baytlarını üretir. `step_budget` aşılırsa `Err(StepBudgetExceeded)`
/// döner; çıktı deterministik olduğu için aynı tarif aynı baytı verir.
pub fn render(recipe: &Recipe) -> Result<Vec<u8>, RenderError> {
    let mut out = Vec::with_capacity(recipe.out_len as usize);
    let mut counter = 0u64;
    let mut steps = 0u32;
    while (out.len() as u32) < recipe.out_len {
        steps = steps.saturating_add(1);
        if steps > recipe.step_budget {
            return Err(RenderError::StepBudgetExceeded {
                used: steps,
                budget: recipe.step_budget,
            });
        }
        let block = prg_block(&recipe.seed, counter);
        counter += 1;
        out.extend_from_slice(&block);
    }
    out.truncate(recipe.out_len as usize);
    // Rezidüel uygula: temel üretim + fark = hedef içerik.
    if !recipe.residual.is_empty() {
        let rlen = recipe.residual.len().min(out.len());
        for (i, byte) in recipe.residual[..rlen].iter().enumerate() {
            out[i] ^= byte;
        }
    }
    Ok(out)
}

/// İçerik commitment'ı: üretim çıktısının hash'i.
pub fn content_hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    StepBudgetExceeded { used: u32, budget: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_recipe() -> Recipe {
        Recipe {
            generator: GeneratorId::Identicon,
            seed: [7u8; 32],
            step_budget: 1_000,
            out_len: 64,
            version: 1,
            residual: Vec::new(),
        }
    }

    #[test]
    fn ayni_tarif_ayni_cikti() {
        let a = render(&sample_recipe()).unwrap();
        let b = render(&sample_recipe()).unwrap();
        assert_eq!(a, b, "determinizm: ayni tarif ayni ciktiyi vermeli");
    }

    #[test]
    fn farkli_tohum_farkli_cikti() {
        let mut r1 = sample_recipe();
        let mut r2 = sample_recipe();
        r1.seed = [1u8; 32];
        r2.seed = [2u8; 32];
        assert_ne!(render(&r1).unwrap(), render(&r2).unwrap());
    }

    #[test]
    fn adim_butcesi_dos_korumasi() {
        let mut r = sample_recipe();
        r.step_budget = 1; // 64 bayt icin 2 blok gerekir -> asilir
        assert!(matches!(
            render(&r),
            Err(RenderError::StepBudgetExceeded { .. })
        ));
    }

    #[test]
    fn reziduel_farki_uygular() {
        let mut r = sample_recipe();
        let base = render(&r).unwrap();
        let mut residual = vec![0u8; 8];
        residual[0] = 0xFF;
        r.residual = residual;
        let with = render(&r).unwrap();
        assert_ne!(base[0], with[0], "reziduel ilk bayti degistirmeli");
        assert_eq!(with[8], base[8], "reziduel disindaki baytlar ayni kalmali");
    }

    #[test]
    fn content_id_deterministik() {
        assert_eq!(sample_recipe().content_id(), sample_recipe().content_id());
    }
}
