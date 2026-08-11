//! Radikal yaklaşım (7f.1 seçenek 2): her içeriği "temel + fark"a indirgemek.
//!
//! Dürüst sınır: Kolmogorov duvarı, organik baytların tariften üretilemeyeceğini
//! söyler. Bu modül bunu ÖLÇER: bir bayt dizisinin, deterministik bir temelden
//! (tohum) ne kadarının üretilebildiğini hesaplar. Geri kalan "fark" rezidüel
//! olarak saklanmalıdır. Böylece:
//! - Yapısal içerik (doku, tekrar, gradyan): fark küçük → neredeyse tamamı CPU
//!   ile üretilir, ağ depolaması ≈ 0.
//! - Gürültü (organik foto/video): fark büyük → baytlar sahipte kalır.
//!
//! Ölçüm metrik: `cover_ratio` = temel üretimle eşleşen bayt oranı. 1.0 =
//! tamamen üretilebilir (ağda 0 bayt); 0.0 = tamamen gürültü (sahipte kalır).

use crate::recipe::prg_block;

/// Sınıflandırma sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadicalClass {
    /// cover_ratio >= 0.95: neredeyse tamamı üretilebilir.
    Regenerable,
    /// cover_ratio >= 0.5: yarısı üretilebilir, fark rezidüelde.
    Hybrid,
    /// cover_ratio < 0.5: organik, baytlar sahipte kalır.
    Organic,
}

/// `content` baytlarının ne kadarının deterministik bir temelden (tohum ile
/// PRG) eşleştiğini ölçer.
///
/// Basit model: her bayt, PRG çıktısının karşılık gelen baytıyla karşılaştırılır.
/// Gerçek sistemde temel, öğrenilmiş bir öncül olur; burada ölçümün omurgası
/// (eşleşme oranı) test edilir.
pub fn cover_ratio(content: &[u8], seed: &[u8; 32]) -> f64 {
    if content.is_empty() {
        return 1.0;
    }
    let mut matches = 0usize;
    let mut counter = 0u64;
    let mut pos = 0usize;
    while pos < content.len() {
        let block = prg_block(seed, counter);
        counter += 1;
        for byte in block {
            if pos >= content.len() {
                break;
            }
            if content[pos] == byte {
                matches += 1;
            }
            pos += 1;
        }
    }
    matches as f64 / content.len() as f64
}

/// Sınıflandırır (eşikler 7f.4'teki dürüst sınırlarla uyumlu).
pub fn classify(content: &[u8], seed: &[u8; 32]) -> RadicalClass {
    let ratio = cover_ratio(content, seed);
    if ratio >= 0.95 {
        RadicalClass::Regenerable
    } else if ratio >= 0.5 {
        RadicalClass::Hybrid
    } else {
        RadicalClass::Organic
    }
}

/// Rezidüel: temel üretimle eşleşmeyen baytların farkı (XOR).
///
/// `Regenerable` sınıfta rezidüel ihmal edilebilir; `Hybrid` sınıfta bu fark
/// zincirde saklanır; `Organic` sınıfta rezidüel = içeriğin kendisi (sahipte).
pub fn residual(content: &[u8], seed: &[u8; 32]) -> Vec<u8> {
    content
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let counter = (i / 32) as u64;
            let idx = i % 32;
            b ^ prg_block(seed, counter)[idx]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_of(v: u8) -> [u8; 32] {
        [v; 32]
    }

    #[test]
    fn yapisal_icerik_regenerable() {
        // 256 bayt: her biri PRG çıktısının ilk baytı -> tam eşleşme
        let seed = seed_of(5);
        let content: Vec<u8> = (0..256u32)
            .flat_map(|c| prg_block(&seed, u64::from(c)))
            .take(256)
            .collect();
        assert_eq!(classify(&content, &seed), RadicalClass::Regenerable);
    }

    #[test]
    fn gurultu_organic() {
        let seed = seed_of(1);
        let content: Vec<u8> = (0..256u16).map(|i| i as u8).collect();
        assert_eq!(classify(&content, &seed), RadicalClass::Organic);
    }

    #[test]
    fn reziduel_ile_tam_geri_getirme() {
        let seed = seed_of(9);
        let content: Vec<u8> = (0..128u8).map(|i| i.wrapping_mul(3)).collect();
        let diff = residual(&content, &seed);
        // content = temel XOR diff; diff XOR temel geri getirir
        let restored: Vec<u8> = (0..content.len())
            .map(|i| {
                let counter = (i / 32) as u64;
                let idx = i % 32;
                diff[i] ^ prg_block(&seed, counter)[idx]
            })
            .collect();
        assert_eq!(restored, content);
    }

    #[test]
    fn cover_ratio_aralikta() {
        let seed = seed_of(2);
        let content = vec![0u8; 64];
        let r = cover_ratio(&content, &seed);
        assert!((0.0..=1.0).contains(&r));
    }
}
