//! Pollen Data Rights - AccessGrant v2 primitives.
//!
//! Kullanıcı metaforu: veri tomurcuğu kullanıcıya aittir; satılan şey tomurcuğun
//! Kendisi değil, o tomurcuğun polenidir. Bu modül bu nedenle `DataAsset` +
//! `AccessGrant` + AI input-ref gate üçlüsünü tanımlar.
//!
//! Güvenlik kuralı: Pollen/B.U.D. verisine işaret eden AI input_ref, geçerli
//! AccessGrant olmadan kabul edilemez. DAO/admin override yoktur.

use crate::core::address::Address;
use crate::storage::content_id::ContentId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{AssetId, GrantId, Signature64};

/// AI input_ref prefix'i. Bu prefix ile başlayan payload'lar Pollen data-ref
/// Sayılır ve strict AccessGrant kontrolünden geçmek zorundadır.
pub const POLLEN_AI_INPUT_REF_PREFIX: &[u8] = b"BDLM_POLLEN_AI_INPUT_REF_V1";

/// DAO-managed encryption policy. DAO can tune protocol parameters, but it
/// Cannot decrypt data, grant read access, or override owner signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionPolicy {
    pub version: u32,
    pub hpke_suite_id: u16,
    pub min_public_key_bytes: u16,
    pub max_grant_duration_blocks: u64,
    pub deprecated_after_block: Option<u64>,
    pub active: bool,
}

impl EncryptionPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.version == 0 {
            return Err("EncryptionPolicy version must be >= 1".into());
        }
        if self.hpke_suite_id == 0 {
            return Err("EncryptionPolicy hpke_suite_id must be non-zero".into());
        }
        if self.min_public_key_bytes < 32 {
            return Err("EncryptionPolicy min_public_key_bytes must be >= 32".into());
        }
        if self.max_grant_duration_blocks == 0 {
            return Err("EncryptionPolicy max_grant_duration_blocks must be >= 1".into());
        }
        if let Some(deprecated) = self.deprecated_after_block {
            if deprecated == 0 {
                return Err("EncryptionPolicy deprecated_after_block cannot be zero".into());
            }
        }
        Ok(())
    }

    pub fn calculate_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_ENCRYPTION_POLICY_V1");
        hasher.update(self.version.to_le_bytes());
        hasher.update(self.hpke_suite_id.to_le_bytes());
        hasher.update(self.min_public_key_bytes.to_le_bytes());
        hasher.update(self.max_grant_duration_blocks.to_le_bytes());
        match self.deprecated_after_block {
            Some(block) => {
                hasher.update([1u8]);
                hasher.update(block.to_le_bytes());
            }
            None => hasher.update([0u8]),
        }
        hasher.update([u8::from(self.active)]);
        hasher.finalize().into()
    }
}

/// SaleAuthorization kimliği = canonical seller authorization hash.
pub type SaleAuthorizationId = AssetId;

/// Owner/seller signed authorization to sell pollen for a DataAsset.
///
/// This is the bridge between "tomurcuk benim" and "polenimi satıyorum":
/// The DataAsset remains owned by `seller`, while grants may be issued under
/// This bounded authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaleAuthorization {
    pub authorization_id: SaleAuthorizationId,
    pub asset_id: AssetId,
    pub seller: Address,
    pub unit_price: u64,
    pub valid_from_block: u64,
    pub expires_at_block: u64,
    pub max_grants: u32,
    #[serde(default)]
    pub grants_issued: u32,
    pub terms_hash: [u8; 32],
    pub seller_signature: Signature64,
}

impl SaleAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new_unsigned(
        asset_id: AssetId,
        seller: Address,
        unit_price: u64,
        valid_from_block: u64,
        expires_at_block: u64,
        max_grants: u32,
        terms_hash: [u8; 32],
    ) -> Self {
        let authorization_id = Self::derive_id(
            &asset_id,
            &seller,
            unit_price,
            valid_from_block,
            expires_at_block,
            max_grants,
            &terms_hash,
        );
        Self {
            authorization_id,
            asset_id,
            seller,
            unit_price,
            valid_from_block,
            expires_at_block,
            max_grants,
            grants_issued: 0,
            terms_hash,
            seller_signature: Signature64::SENTINEL,
        }
    }

    pub fn derive_id(
        asset_id: &AssetId,
        seller: &Address,
        unit_price: u64,
        valid_from_block: u64,
        expires_at_block: u64,
        max_grants: u32,
        terms_hash: &[u8; 32],
    ) -> SaleAuthorizationId {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_SALE_AUTHORIZATION_V1");
        hasher.update(asset_id.0);
        hasher.update(seller.as_bytes());
        hasher.update(unit_price.to_le_bytes());
        hasher.update(valid_from_block.to_le_bytes());
        hasher.update(expires_at_block.to_le_bytes());
        hasher.update(max_grants.to_le_bytes());
        hasher.update(terms_hash);
        AssetId(hasher.finalize().into())
    }

    /// Signing hash for wallets. This deliberately excludes `seller_signature`
    /// And mutable `grants_issued`.
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_SALE_AUTHORIZATION_SIGNING_V1");
        hasher.update(self.authorization_id.0);
        hasher.update(self.asset_id.0);
        hasher.update(self.seller.as_bytes());
        hasher.update(self.unit_price.to_le_bytes());
        hasher.update(self.valid_from_block.to_le_bytes());
        hasher.update(self.expires_at_block.to_le_bytes());
        hasher.update(self.max_grants.to_le_bytes());
        hasher.update(self.terms_hash);
        hasher.finalize().into()
    }

    pub fn validate_shape(&self) -> Result<(), String> {
        if self.authorization_id == SaleAuthorizationId::zero() {
            return Err("SaleAuthorization authorization_id cannot be zero".into());
        }
        if self.asset_id == AssetId::zero() {
            return Err("SaleAuthorization asset_id cannot be zero".into());
        }
        if self.seller == Address::zero() {
            return Err("SaleAuthorization seller cannot be zero".into());
        }
        if self.unit_price == 0 {
            return Err("SaleAuthorization unit_price must be >= 1".into());
        }
        if self.expires_at_block <= self.valid_from_block {
            return Err("SaleAuthorization expires_at_block must be after valid_from_block".into());
        }
        if self.max_grants == 0 {
            return Err("SaleAuthorization max_grants must be >= 1".into());
        }
        if self.grants_issued > self.max_grants {
            return Err("SaleAuthorization grants_issued exceeds max_grants".into());
        }
        if self.seller_signature.is_sentinel() {
            return Err("SaleAuthorization seller_signature sentinel is invalid".into());
        }
        let expected = Self::derive_id(
            &self.asset_id,
            &self.seller,
            self.unit_price,
            self.valid_from_block,
            self.expires_at_block,
            self.max_grants,
            &self.terms_hash,
        );
        if self.authorization_id != expected {
            return Err("SaleAuthorization id does not match canonical preimage".into());
        }
        Ok(())
    }

    /// Satıcının imzasını `signing_hash()` üzerinde kriptografik olarak
    /// Doğrular.
    ///
    /// Strix bulgusu (HIGH, CWE-347): `validate_shape()` yalnızca sıfır
    /// Sentinel'ini reddediyordu, yani sıfırdan farklı **herhangi** 64 bayt
    /// Geçerli satıcı rızası sayılıyordu. Saldırgan `[1u8; 64]` yazıp başkasının
    /// Varlığı için satış yetkisi kaydettirebiliyordu.
    ///
    /// B.U.D.'da adres, Ed25519 açık anahtarının ta kendisidir
    /// (`Address::from(keypair.public_key_bytes())`, `core/transaction.rs:564`),
    /// Bu yüzden ayrı bir anahtar kaydına gerek yok: `seller` alanı doğrulama
    /// Anahtarıdır.
    pub fn verify_seller_signature(&self) -> Result<(), String> {
        if self.seller_signature.is_sentinel() {
            return Err("SaleAuthorization seller_signature sentinel is invalid".into());
        }
        crate::crypto::primitives::verify_signature(
            &self.signing_hash(),
            &self.seller_signature.0,
            self.seller.as_bytes(),
        )
        .map_err(|e| format!("SaleAuthorization seller_signature is not a valid signature by seller: {e}"))
    }

    /// Şekil kontrolü **ve** imza doğrulaması. Zincir/kayıt yolları bunu
    /// Çağırmalı; çıplak `validate_shape()` yalnızca imza dışı alanları bakar.
    pub fn validate_authenticated(&self) -> Result<(), String> {
        self.validate_shape()?;
        self.verify_seller_signature()
    }

    pub fn can_issue(&self, current_block: u64) -> bool {
        current_block >= self.valid_from_block
            && current_block <= self.expires_at_block
            && self.grants_issued < self.max_grants
    }

    pub fn record_issued_grant(&mut self) -> Result<(), String> {
        if self.grants_issued >= self.max_grants {
            return Err("SaleAuthorization grant limit exhausted".into());
        }
        self.grants_issued = self.grants_issued.saturating_add(1);
        Ok(())
    }

    pub fn calculate_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_SALE_AUTHORIZATION_LEAF_V1");
        hasher.update(self.authorization_id.0);
        hasher.update(self.asset_id.0);
        hasher.update(self.seller.as_bytes());
        hasher.update(self.unit_price.to_le_bytes());
        hasher.update(self.valid_from_block.to_le_bytes());
        hasher.update(self.expires_at_block.to_le_bytes());
        hasher.update(self.max_grants.to_le_bytes());
        hasher.update(self.grants_issued.to_le_bytes());
        hasher.update(self.terms_hash);
        hasher.update(self.seller_signature.as_bytes());
        hasher.finalize().into()
    }
}

/// DataAsset lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DataAssetStatus {
    #[default]
    Active,
    Revoked,
}

/// Kullanıcının satılabilir veri varlığı. Varlık satılmaz; erişim poleni
/// AccessGrant ile satılır.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataAsset {
    pub asset_id: AssetId,
    pub owner: Address,
    pub manifest_id: ContentId,
    pub metadata_commitment: [u8; 32],
    pub encrypted: bool,
    #[serde(default)]
    pub status: DataAssetStatus,
}

impl DataAsset {
    pub fn new(
        owner: Address,
        manifest_id: ContentId,
        metadata_commitment: [u8; 32],
        encrypted: bool,
    ) -> Self {
        let asset_id = Self::derive_id(&owner, &manifest_id, &metadata_commitment);
        Self {
            asset_id,
            owner,
            manifest_id,
            metadata_commitment,
            encrypted,
            status: DataAssetStatus::Active,
        }
    }

    pub fn derive_id(
        owner: &Address,
        manifest_id: &ContentId,
        metadata_commitment: &[u8; 32],
    ) -> AssetId {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_DATA_ASSET_V1");
        hasher.update(owner.as_bytes());
        hasher.update(manifest_id.0);
        hasher.update(metadata_commitment);
        AssetId(hasher.finalize().into())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.asset_id == AssetId::zero() {
            return Err("DataAsset asset_id cannot be zero".into());
        }
        if self.owner == Address::zero() {
            return Err("DataAsset owner cannot be zero".into());
        }
        let expected = Self::derive_id(&self.owner, &self.manifest_id, &self.metadata_commitment);
        if self.asset_id != expected {
            return Err("DataAsset asset_id does not match canonical preimage".into());
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.status == DataAssetStatus::Active
    }

    pub fn calculate_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_DATA_ASSET_LEAF_V1");
        hasher.update(self.asset_id.0);
        hasher.update(self.owner.as_bytes());
        hasher.update(self.manifest_id.0);
        hasher.update(self.metadata_commitment);
        hasher.update([u8::from(self.encrypted)]);
        hasher.update([match self.status {
            DataAssetStatus::Active => 1,
            DataAssetStatus::Revoked => 2,
        }]);
        hasher.finalize().into()
    }
}

/// AccessGrant lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AccessGrantStatus {
    #[default]
    Active,
    Revoked,
}

/// Owner-imzalı veri erişim izni. `grantee`, veri polenini satın alan AI ajanı
/// Veya kullanıcıdır. `max_reads` on-chain okuma tüketim sınırıdır.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessGrant {
    pub grant_id: GrantId,
    pub asset_id: AssetId,
    pub owner: Address,
    pub grantee: Address,
    pub payer: Address,
    pub price_paid: u64,
    pub issued_at_block: u64,
    pub expires_at_block: u64,
    pub max_reads: u32,
    #[serde(default)]
    pub reads_used: u32,
    pub purpose_hash: [u8; 32],
    #[serde(default)]
    pub status: AccessGrantStatus,
    pub owner_signature: Signature64,
    /// Bu izin, sahibin doğrudan imzası yerine kayıtlı bir
    /// [`SaleAuthorization`] üzerinden türetildiyse o yetkinin kimliği.
    ///
    /// `None` = doğrudan sahip imzası; `owner_signature` kriptografik olarak
    /// Doğrulanır. `Some(id)` = yetki-dayanaklı izin; sahiplik rızası, kayıt
    /// Sırasında satıcı imzası doğrulanmış olan o yetkiden gelir. Bu ayrım
    /// Alanın kendisinde durur, çünkü iki durumda *neyin* doğrulandığı
    /// Farklıdır ve bunu çağıranın hatırlamasına bırakmak, bulgunun ta
    /// Kendisiydi.
    #[serde(default)]
    pub authorized_by: Option<SaleAuthorizationId>,
}

impl AccessGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn new_unsigned(
        asset_id: AssetId,
        owner: Address,
        grantee: Address,
        payer: Address,
        price_paid: u64,
        issued_at_block: u64,
        expires_at_block: u64,
        max_reads: u32,
        purpose_hash: [u8; 32],
    ) -> Self {
        let grant_id = Self::derive_id(
            &asset_id,
            &owner,
            &grantee,
            &payer,
            price_paid,
            issued_at_block,
            expires_at_block,
            max_reads,
            &purpose_hash,
        );
        Self {
            grant_id,
            asset_id,
            owner,
            grantee,
            payer,
            price_paid,
            issued_at_block,
            expires_at_block,
            max_reads,
            reads_used: 0,
            purpose_hash,
            status: AccessGrantStatus::Active,
            owner_signature: Signature64::SENTINEL,
            authorized_by: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn derive_id(
        asset_id: &AssetId,
        owner: &Address,
        grantee: &Address,
        payer: &Address,
        price_paid: u64,
        issued_at_block: u64,
        expires_at_block: u64,
        max_reads: u32,
        purpose_hash: &[u8; 32],
    ) -> GrantId {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_ACCESS_GRANT_V1");
        hasher.update(asset_id.0);
        hasher.update(owner.as_bytes());
        hasher.update(grantee.as_bytes());
        hasher.update(payer.as_bytes());
        hasher.update(price_paid.to_le_bytes());
        hasher.update(issued_at_block.to_le_bytes());
        hasher.update(expires_at_block.to_le_bytes());
        hasher.update(max_reads.to_le_bytes());
        hasher.update(purpose_hash);
        AssetId(hasher.finalize().into())
    }

    pub fn validate_shape(&self) -> Result<(), String> {
        if self.grant_id == GrantId::zero() {
            return Err("AccessGrant grant_id cannot be zero".into());
        }
        if self.asset_id == AssetId::zero() {
            return Err("AccessGrant asset_id cannot be zero".into());
        }
        if self.owner == Address::zero()
            || self.grantee == Address::zero()
            || self.payer == Address::zero()
        {
            return Err("AccessGrant addresses cannot be zero".into());
        }
        if self.expires_at_block <= self.issued_at_block {
            return Err("AccessGrant expires_at_block must be after issued_at_block".into());
        }
        if self.max_reads == 0 {
            return Err("AccessGrant max_reads must be >= 1".into());
        }
        if self.authorized_by.is_none() && self.owner_signature.is_sentinel() {
            return Err("AccessGrant owner_signature sentinel is invalid".into());
        }
        let expected = Self::derive_id(
            &self.asset_id,
            &self.owner,
            &self.grantee,
            &self.payer,
            self.price_paid,
            self.issued_at_block,
            self.expires_at_block,
            self.max_reads,
            &self.purpose_hash,
        );
        if self.grant_id != expected {
            return Err("AccessGrant grant_id does not match canonical preimage".into());
        }
        Ok(())
    }

    /// Sahibin imzaladığı kanonik özet. `owner_signature`, değişebilen
    /// `reads_used` ve `status` alanları kasten dışarıda: imza izin verilen
    /// *şekli* bağlar, o iznin çalışma-zamanı sayaçlarını değil.
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_ACCESS_GRANT_SIGNING_V1");
        hasher.update(self.grant_id.0);
        hasher.update(self.asset_id.0);
        hasher.update(self.owner.as_bytes());
        hasher.update(self.grantee.as_bytes());
        hasher.update(self.payer.as_bytes());
        hasher.update(self.price_paid.to_le_bytes());
        hasher.update(self.issued_at_block.to_le_bytes());
        hasher.update(self.expires_at_block.to_le_bytes());
        hasher.update(self.max_reads.to_le_bytes());
        hasher.update(self.purpose_hash);
        // Yetki-kaynağı imzanın kapsamında: aksi halde saldırgan, sahibin
        // İmzaladığı bir izni alıp `authorized_by`'ı doldurarak imza
        // Kontrolünü atlatabilirdi.
        match &self.authorized_by {
            None => hasher.update([0u8]),
            Some(id) => {
                hasher.update([1u8]);
                hasher.update(id.0);
            }
        }
        hasher.finalize().into()
    }

    /// Sahibin imzasını `signing_hash()` üzerinde kriptografik olarak doğrular.
    /// Gerekçe [`SaleAuthorization::verify_seller_signature`] ile aynı: sıfır
    /// Olmayan rastgele baytlar rıza değildir.
    pub fn verify_owner_signature(&self) -> Result<(), String> {
        if self.authorized_by.is_some() {
            // Yetki-dayanaklı izinde imzalanan şey bu izin değil, ona kaynak
            // Olan satış yetkisidir; o imza `MarketplaceRegistry` tarafından
            // Yetki kaydedilirken doğrulanmıştır. Bu izinler yalnızca
            // `issue_grant_from_sale_authorization` üzerinden üretilir;
            // `create_access_grant` dışarıdan gelen böyle bir izni reddeder.
            return Ok(());
        }
        if self.owner_signature.is_sentinel() {
            return Err("AccessGrant owner_signature sentinel is invalid".into());
        }
        crate::crypto::primitives::verify_signature(
            &self.signing_hash(),
            &self.owner_signature.0,
            self.owner.as_bytes(),
        )
        .map_err(|e| format!("AccessGrant owner_signature is not a valid signature by owner: {e}"))
    }

    /// Şekil kontrolü **ve** imza doğrulaması.
    pub fn validate_authenticated(&self) -> Result<(), String> {
        self.validate_shape()?;
        self.verify_owner_signature()
    }

    pub fn is_active_for(&self, grantee: &Address, current_block: u64) -> bool {
        self.status == AccessGrantStatus::Active
            && &self.grantee == grantee
            && current_block <= self.expires_at_block
            && self.reads_used < self.max_reads
    }

    pub fn record_read(&mut self) -> Result<(), String> {
        if self.reads_used >= self.max_reads {
            return Err("AccessGrant read limit exhausted".into());
        }
        self.reads_used = self.reads_used.saturating_add(1);
        Ok(())
    }

    pub fn calculate_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_ACCESS_GRANT_LEAF_V1");
        hasher.update(self.grant_id.0);
        hasher.update(self.asset_id.0);
        hasher.update(self.owner.as_bytes());
        hasher.update(self.grantee.as_bytes());
        hasher.update(self.payer.as_bytes());
        hasher.update(self.price_paid.to_le_bytes());
        hasher.update(self.issued_at_block.to_le_bytes());
        hasher.update(self.expires_at_block.to_le_bytes());
        hasher.update(self.max_reads.to_le_bytes());
        hasher.update(self.reads_used.to_le_bytes());
        hasher.update(self.purpose_hash);
        hasher.update([match self.status {
            AccessGrantStatus::Active => 1,
            AccessGrantStatus::Revoked => 2,
        }]);
        hasher.update(self.owner_signature.as_bytes());
        hasher.finalize().into()
    }
}

/// Canonical reference embedded in `AiInferenceRequest.input_ref` when the
/// Request wants to read a Pollen/B.U.D. DataAsset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AiDataInputRef {
    pub asset_id: AssetId,
    pub grant_id: GrantId,
}

impl AiDataInputRef {
    pub const ENCODED_LEN: usize = POLLEN_AI_INPUT_REF_PREFIX.len() + 32 + 32;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(POLLEN_AI_INPUT_REF_PREFIX);
        out.extend_from_slice(&self.asset_id.0);
        out.extend_from_slice(&self.grant_id.0);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, String> {
        if !bytes.starts_with(POLLEN_AI_INPUT_REF_PREFIX) {
            return Ok(None);
        }
        if bytes.len() != Self::ENCODED_LEN {
            return Err(format!(
                "Malformed Pollen AI input_ref: expected {} bytes, got {}",
                Self::ENCODED_LEN,
                bytes.len()
            ));
        }
        let mut asset = [0u8; 32];
        let mut grant = [0u8; 32];
        let offset = POLLEN_AI_INPUT_REF_PREFIX.len();
        asset.copy_from_slice(&bytes[offset..offset + 32]);
        grant.copy_from_slice(&bytes[offset + 32..offset + 64]);
        Ok(Some(Self {
            asset_id: AssetId(asset),
            grant_id: AssetId(grant),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B.U.D. adresi = Ed25519 açık anahtarı, bu yüzden test adresleri de
    /// Gerçek anahtarlardan türetilmeli; aksi halde imza doğrulaması hiçbir
    /// Testte sınanamaz.
    fn keypair(byte: u8) -> crate::crypto::primitives::KeyPair {
        crate::crypto::primitives::KeyPair::from_seed(&[byte; 32])
            .expect("deterministik test tohumu geçerli bir Ed25519 anahtarı vermeli")
    }

    fn addr(byte: u8) -> Address {
        Address::from(keypair(byte).public_key_bytes())
    }

    #[test]
    fn data_asset_id_is_deterministic() {
        let cid = ContentId::of(b"bud-data");
        let asset = DataAsset::new(addr(1), cid, [9u8; 32], true);
        assert_eq!(
            asset.asset_id,
            DataAsset::derive_id(&addr(1), &cid, &[9u8; 32])
        );
        assert!(asset.validate().is_ok());
    }

    #[test]
    fn access_grant_sentinel_signature_rejected() {
        let grant = AccessGrant::new_unsigned(
            AssetId::from([3u8; 32]),
            addr(1),
            addr(2),
            addr(2),
            10,
            1,
            10,
            1,
            [7u8; 32],
        );
        assert!(grant.validate_shape().unwrap_err().contains("sentinel"));
    }

    #[test]
    fn sale_authorization_id_and_signing_hash_are_stable() {
        let mut auth = SaleAuthorization::new_unsigned(
            AssetId::from([6u8; 32]),
            addr(1),
            99,
            10,
            20,
            2,
            [3u8; 32],
        );
        assert_eq!(
            auth.authorization_id,
            SaleAuthorization::derive_id(
                &AssetId::from([6u8; 32]),
                &addr(1),
                99,
                10,
                20,
                2,
                &[3u8; 32]
            )
        );
        let signing_hash = auth.signing_hash();
        auth.seller_signature = Signature64::from([1u8; 64]);
        assert_eq!(signing_hash, auth.signing_hash());
        assert!(auth.validate_shape().is_ok());
        assert!(auth.can_issue(10));
        auth.record_issued_grant().unwrap();
        auth.record_issued_grant().unwrap();
        assert!(!auth.can_issue(10));
    }

    #[test]
    fn encryption_policy_validates_without_decrypt_authority() {
        let policy = EncryptionPolicy {
            version: 1,
            hpke_suite_id: 0x20,
            min_public_key_bytes: 32,
            max_grant_duration_blocks: 100,
            deprecated_after_block: None,
            active: true,
        };
        assert!(policy.validate().is_ok());
        let json = serde_json::to_string(&policy).unwrap();
        assert!(!json.contains("decrypt"));
        assert!(!json.contains("private"));
        assert!(!json.contains("override"));
    }

    #[test]
    fn encryption_policy_rejects_zero_duration() {
        let policy = EncryptionPolicy {
            version: 1,
            hpke_suite_id: 0x20,
            min_public_key_bytes: 32,
            max_grant_duration_blocks: 0,
            deprecated_after_block: None,
            active: true,
        };
        assert!(policy.validate().unwrap_err().contains("duration"));
    }

    #[test]
    fn sale_authorization_sentinel_signature_rejected() {
        let auth = SaleAuthorization::new_unsigned(
            AssetId::from([6u8; 32]),
            addr(1),
            99,
            10,
            20,
            2,
            [3u8; 32],
        );
        assert!(auth.validate_shape().unwrap_err().contains("sentinel"));
    }

    #[test]
    fn ai_data_input_ref_roundtrip_and_malformed() {
        let reference = AiDataInputRef {
            asset_id: AssetId::from([4u8; 32]),
            grant_id: GrantId::from([5u8; 32]),
        };
        let encoded = reference.encode();
        assert_eq!(AiDataInputRef::decode(&encoded).unwrap(), Some(reference));
        assert_eq!(AiDataInputRef::decode(b"plain prompt").unwrap(), None);
        let mut malformed = POLLEN_AI_INPUT_REF_PREFIX.to_vec();
        malformed.push(1);
        assert!(AiDataInputRef::decode(&malformed).is_err());
    }

    /// İmza doğrulaması gerçekten çalışıyor: sahibin kendi anahtarıyla
    /// İmzaladığı izin geçerli, tek bayt değiştirilmiş hali geçersiz.
    #[test]
    fn an_owner_signed_grant_verifies_and_a_tampered_one_does_not() {
        let owner = keypair(1);
        let mut grant = AccessGrant::new_unsigned(
            AssetId::from([3u8; 32]),
            Address::from(owner.public_key_bytes()),
            addr(2),
            addr(2),
            10,
            1,
            10,
            1,
            [7u8; 32],
        );
        grant.owner_signature = Signature64::from(owner.sign(&grant.signing_hash()));
        grant
            .validate_authenticated()
            .expect("sahibin kendi imzası doğrulanmalı");

        let mut bad = grant.clone();
        bad.owner_signature.0[0] ^= 0x01;
        assert!(
            bad.validate_authenticated().is_err(),
            "tek bayt bozulmuş imza reddedilmeli"
        );
    }

    /// Sıfır olmayan uydurma baytlar rıza sayılmaz - bulgunun özü.
    #[test]
    fn nonzero_garbage_is_not_a_signature() {
        let mut auth = SaleAuthorization::new_unsigned(
            AssetId::from([6u8; 32]),
            addr(1),
            99,
            10,
            20,
            2,
            [3u8; 32],
        );
        auth.seller_signature = Signature64::from([1u8; 64]);
        // Şekil kontrolü geçer - o katman imza bilmez.
        assert!(auth.validate_shape().is_ok());
        // Kimlik doğrulamalı kontrol geçmez.
        let err = auth
            .validate_authenticated()
            .expect_err("uydurma baytlar geçerli satıcı imzası sayılmamalı");
        assert!(err.contains("not a valid signature by seller"), "alınan: {err}");
    }

    /// Yetki-dayanaklı izinde sentinel imza meşrudur; rıza kaynağı ayrı
    /// Alanda kayıtlıdır ve imza doğrulaması o yetkinin kaydında yapılmıştır.
    #[test]
    fn an_authorization_backed_grant_may_carry_no_signature() {
        let mut grant = AccessGrant::new_unsigned(
            AssetId::from([3u8; 32]),
            addr(1),
            addr(2),
            addr(2),
            10,
            1,
            10,
            1,
            [7u8; 32],
        );
        grant.authorized_by = Some(SaleAuthorizationId::from([5u8; 32]));
        grant.grant_id = AccessGrant::derive_id(
            &grant.asset_id,
            &grant.owner,
            &grant.grantee,
            &grant.payer,
            grant.price_paid,
            grant.issued_at_block,
            grant.expires_at_block,
            grant.max_reads,
            &grant.purpose_hash,
        );
        grant
            .validate_authenticated()
            .expect("yetki-dayanaklı izin kendi imzasını taşımak zorunda değil");
    }

    /// Yetki kaynağı imzanın kapsamında: `authorized_by` değişince özet de
    /// Değişmeli, yoksa sahibin imzaladığı bir izin yetki-dayanaklıya
    /// Dönüştürülüp imza kontrolü atlatılabilirdi.
    #[test]
    fn the_authorization_source_is_bound_by_the_signing_hash() {
        let mut grant = AccessGrant::new_unsigned(
            AssetId::from([3u8; 32]),
            addr(1),
            addr(2),
            addr(2),
            10,
            1,
            10,
            1,
            [7u8; 32],
        );
        let direct = grant.signing_hash();
        grant.authorized_by = Some(SaleAuthorizationId::from([5u8; 32]));
        assert_ne!(direct, grant.signing_hash());
    }
}
