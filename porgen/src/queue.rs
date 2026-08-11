//! Üretim kuyruğu: hangi manifest'in ne zaman üretileceğini belirler.
//!
//! KTT (konsensüs-türetilmiş talep sinyali) deseni: sıralama, düğüm-yerel
//! sayaçlara değil, finalized geçmişten deterministik hesaplanan bir önceliğe
//! dayanır. Çapraz-domain ağırlığı: her domain'in finality gücü (BFT güçlü,
//! PoW zayıf) üretim önceliğini çarpar - Budlum'un `DomainFinalityAdapter`
//! iskeletinin depolama görevine uygulanması.

use sha2::Digest;

/// Domain finality gücü (0..1): üretim önceliğini ağırlıklandırır.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityWeight(pub u32); // 0..=1000

/// Üretim kuyruğu girdisi.
#[derive(Debug, Clone)]
pub struct QueueEntry {
    pub manifest_id: [u8; 32],
    /// Son okuma epoch'u (finalized sinyalin parçası).
    pub last_read_epoch: u64,
    /// Son okumadan bu yana okuma sayısı.
    pub read_count: u64,
    /// İçeriğin yaşı (epoch).
    pub age_epochs: u64,
    /// Üretim maliyeti (adım bütçesi) - üretim önceliği maliyetle ters orantılı.
    pub cost_steps: u64,
    /// İçeriğin ait olduğu domain'in finality ağırlığı.
    pub domain_weight: FinalityWeight,
}

impl QueueEntry {
    /// Deterministik öncelik puanı. Yüksek puan = önce üretilir.
    ///
    /// Bileşenler:
    /// - talep: `read_count` log ölçeğinde (viral içerik öne geçer);
    /// - tazelik: son okuma ne kadar yakınsa o kadar öncelikli;
    /// - soğuma: yaş arttıkça puan düşer (Z1 awake/asleep deseni);
    /// - maliyet: pahalı üretim ertelenir;
    /// - domain: güçlü finality (BFT) daha yüksek ağırlık taşır.
    ///
    /// Kayan nokta yok: tüm aritmetik tamsayı; `read_count` için log2.
    pub fn priority(&self) -> u64 {
        let log_reads = u64::from((self.read_count.max(1)).ilog2()); // 0..~63
        let freshness = 1_000_000u64.saturating_sub(self.age_epochs.saturating_mul(10));
        let cost_penalty = self.cost_steps.min(10_000) / 100; // 0..100
        let demand = log_reads.saturating_mul(100_000);
        let domain = u64::from(self.domain_weight.0); // 0..1000
        demand
            .saturating_add(freshness)
            .saturating_sub(cost_penalty)
            .saturating_add(domain)
    }
}

/// Kuyruğu önceliğe göre sıralar (deterministik: eşit puan manifest_id'ye göre).
pub fn order(entries: &[QueueEntry]) -> Vec<QueueEntry> {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| {
        let pa = a.priority();
        let pb = b.priority();
        pb.cmp(&pa).then_with(|| a.manifest_id.cmp(&b.manifest_id))
    });
    sorted
}

/// Üretim kuyruğunun deterministik "plan imzası": aynı girdiler aynı sırayı
/// verir. Bu imza zincirde yayınlanır; tüm düğümler aynı sırayı üretir.
pub fn plan_signature(ordered: &[QueueEntry]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(b"BUD_PORGEN_QUEUE_V1");
    for e in ordered {
        h.update(e.manifest_id);
        h.update(e.priority().to_le_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipe::{GeneratorId, Recipe};

    fn entry(reads: u64, age: u64, weight: u32) -> QueueEntry {
        let recipe = Recipe {
            generator: GeneratorId::Identicon,
            seed: [0u8; 32],
            step_budget: 1_000,
            out_len: 64,
            version: 1,
            residual: Vec::new(),
        };
        QueueEntry {
            manifest_id: recipe.content_id(),
            last_read_epoch: 0,
            read_count: reads,
            age_epochs: age,
            cost_steps: 500,
            domain_weight: FinalityWeight(weight),
        }
    }

    #[test]
    fn viral_icerik_once_uretilir() {
        let hot = entry(1_000_000, 1, 500);
        let cold = entry(1, 100, 500);
        let ordered = order(&[cold.clone(), hot.clone()]);
        assert_eq!(ordered[0].manifest_id, hot.manifest_id);
    }

    #[test]
    fn guclu_finality_once_uretilir() {
        let bft = entry(10, 10, 900);
        let pow = entry(10, 10, 100);
        let ordered = order(&[pow.clone(), bft.clone()]);
        assert_eq!(ordered[0].manifest_id, bft.manifest_id);
    }

    #[test]
    fn plan_imzasi_deterministik() {
        let es = vec![entry(5, 5, 500), entry(9, 2, 700)];
        let s1 = plan_signature(&order(&es));
        let s2 = plan_signature(&order(&es));
        assert_eq!(s1, s2);
    }

    #[test]
    fn yasli_icerik_soğur() {
        let fresh = entry(10, 1, 500);
        let old = entry(10, 100_000, 500);
        let ordered = order(&[old.clone(), fresh.clone()]);
        assert_eq!(ordered[0].manifest_id, fresh.manifest_id);
    }
}
