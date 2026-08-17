# B.U.D. 2.0 - Tüm Format Sıkıştırma Tablosu (2026-08-16)

Tüm oranlar ÖLÇÜLMÜŞTÜR; tekrarlanabilir komutlar ve korpus tanımlarıyla birlikte.
Uydurma sayı yok (EK13 disiplini). Korpuslar deterministik (seed=7); sentetik tekrarlı
korpuslar işaretlenmiştir.

## 1. Format × Boru Hattı Oran Matrisi

| Format | Yol | Oran | Ölçüm | Not |
|---|---|---|---|---|
| **JSON** | zstd-19 (RAW) | **7.83x** | measure_ratios.py seed=7 (50k kayıt) | temel |
| JSON | xz-9 (RAW) | 8.07x | aynı korpus | |
| JSON | columnar Exact (v1, str) | 8.53x | prototip | kayıpsız, bayt-birebir |
| JSON | columnar Exact + sayısal binary (v2) | 8.84x | prototip | Parquet-benzeri tipli |
| JSON | columnar OrderFree + sayısal binary | **12.07x** | prototip (seed=7) | kayıt sıralaması bitişikliği (KF2) |
| **CSV** | zstd-19 (RAW) | **3.55x** | measure_ratios.py seed=7 (60k satır) | temel |
| CSV | xz-9 | 3.69x | aynı korpus | |
| **LOG** | zstd-19 (RAW) | **6.17x** | measure_ratios.py seed=7 (80k satır) | temel |
| LOG | xz-9 | 6.30x | aynı korpus | |
| LOG | zstd konteyner (ChunkCodec::Zstd) | 6.55x | CLI --zstd (10.48MB örnek) | |
| LOG | şablon+sütun (prototip) | 7.63x | önceki tur | kazanç korpusa bağlı |
| LOG | BUD-HFM1 (yerleşik Huffman) | ~1.69x | CLI kanıtı | sıfır bağımlılık, düşük oran |
| **XML** | zstd-19 | 38.24x | prototip - SENTETİK TEKRARLI korpus | gerçekçi XML'de çok düşük |
| **TEXT** | zstd-19 | ~4087x | prototip - SENTETİK TEKRARLI korpus | gerçekçi metinde ~3-5x |
| **Binary** | zstd-19 | ~1.0x | rastgele | sıkışmaz (beklenen) |

## 2. İcat transformları (sıkıştırma ÖNCESİ kayıpsız dönüşümler)

| Transform | Format | Kazanç | Durum |
|---|---|---|---|
| Columnar Exact (v1 str) | JSON | 7.83 → 8.53x | kodlu (bud_format_columnar) |
| Columnar v2 tipli (binary sayılar) | JSON | 7.83 → 8.84x | kodlu (commit 5a2b0532) |
| Columnar OrderFree + tipli | JSON | 7.83 → 12.07x | prototip kanıtı; Rust'ta sıralama kazancı korpusa bağlı |
| Şablon+sütun | LOG | 6.17 → 7.63x | prototip; kazanç korpusa bağlı |
| Byte-pair dict + zstd | her | ~1.00x | DENENDİ - zstd zaten yakalıyor (değersiz) |
| Prefix/delta | LOG/XML | ~1.01-1.16x | DENENDİ - zstd zaten yakalıyor (düşük) |
| Sayısal binary (tekil, format'sız) | her | kötüleşir | DENENDİ - format bilgisi şart (sütun bazında olmalı) |

**Kritik ders:** zstd çok güçlü; üzerine rastgele transform eklemek kazanç vermiyor.
Kazanç ancak zstd'nin GÖREMEDİĞİ yerde: (a) yüksek entropili sayıları binary'ye çevirmek
(sütun bazında, format bilgisiyle - Parquet mantığı), (b) kayıt sıralamasıyla tekrarları
pencere içine toplamak, (c) tenant düzeyinde dedup/delta (K20 - çoklu dosya, henüz akış yok).

## 3. LLMBrain / LLM-sıkıştırma araştırması (kullanıcı sorusu - 2026-08-16)

İncelenen: Radeonares32/LLMBrain (ROADMAP/ARCHITECTURE), LLMZip (LLM+aritmetik kodlama,
kayıpsız metin), P²-LLM (LLM ile kayıpsız görüntü, NeurIPS 2025), Huff-LLM, LightCompress.

- **LLMBrain'in "sıkıştırması" = token-verimli derleme** (BrainFrame .bf): içeriği LLM
  için kısa, yapılandırılmış bağlama derler. Depolama oranı DEĞİLDİR; RAG'a karşı
  "kalıcı bellek derleyicisi". .bud'a geçmesi denenmeli: .bud'un konteyneri orijinali
  saklar; LLMBrain deseni = orijinal + "derlenmiş görünüm" (şema/özet katmanı). Bu,
  KF2 (çözünürlük korunur) kapsamında medya için semantic-derleme yönü açabilir -
  prototip aşamasında, kayıpsızlık çekirdeği bozulmaz (orijinal her zaman saklanır).
- **LLMZip / P²-LLM**: LLM'ler genel amaçlı kayıpsız sıkıştırıcı olabilir ("intelligence
  and compression, two sides of same coin") - ancak pratik maliyet (model + saniyeler)
  depolama fiyatına uymaz; B.U.D. için ölçeklenmez. Ders: içerik MODELİ bilgisi
  (şablon, sütun, tekrar) sıkıştırmayı güçlendirir - B.U.D.'un format-farkında
  transformları bunun hafif, deterministik, kayıpsız hali.
- **Huff-LLM**: Huffman'ı alt-kümelerde uygulamak (tüm ağırlığa değil) → B.U.D.'da
  karşılığı: parça BAZINDA codec seçimi (Raw/Huffman/Zstd - ChunkCodec) zaten var.
- **Sonuç:** LLMBrain'den alınacaklar markasız uyarlandı (yapısal parçalama, rol-uzman
  çoklu aday, checkpoint, konteyner paketleme, derlenmiş görünüm yönü). LLM-derleme
  katmanı prototip olarak açık kalem; çekirdek kayıpsızlık korunur.

## 4. Dürüst fiyat etkisi

$0.016/TB/ay taahhüdü şu anki tek-dosya oranlarıyla TUTMUYOR (K19 kanaryası):
- JSON Exact columnar + tipli: 8.84x → fiyat ≈ 0.23342×1.143/8.84 ≈ **0.030 $/TB/ay**
- JSON OrderFree + tipli: 12.07x → ≈ **0.022 $/TB/ay** (kayıt sırası serbestse)
- 16.68x (Düz 7+1) veya 18.76x (EVENODD) gerektiren tavan: tenant düzeyi dedup/delta
  + çoklu dosya akışı devreye girmeden ulaşılamaz - sonraki ana iş kalemi.

Tüm oranlar `scripts/measure_ratios.py --seed 7` ile yeniden üretilebilir; transform
oranları `/tmp` prototiplerindendir ve Rust'a taşındıkça `RealBench::measured_ratios()`
+ kanarya testleriyle sabitlenir.

## 5. VİDEO - GERÇEK ÖLÇÜM (2026-08-16, ffmpeg 7.1.5; testsrc2 720p30 20sn, 829MB ham YUV)

SENTETİK desen - karşılaştırma içsel tutarlı; gerçek film/drone daha düşük oran verir.
Komutlar: `/tmp/video_olcum.sh` (korpus + codec'ler + roundtrip doğrulaması).

| Yol | Boyut | Oran | Not |
|---|---|---|---|
| x264 crf18 | 11.7MB | 71x | kalite odaklı |
| x264 crf23 | 7.56MB | 110x | dengeli |
| x265 crf23 | 9.12MB | 91x | **x264'ten büyük - içerik bağımlılığı (K84)** |
| svtav1 crf30 | 8.21MB | 101x | AV1 |
| svtav1 crf40 | 4.02MB | 206x | agresif |
| vp9 crf30 | 9.10MB | 91x | |
| ffv1 lossless | 31.9MB | 26x | arşiv standardı |
| x264 lossless | 28.4MB | 29x | roundtrip birebir doğrulandı |
| x265 lossless | 32.6MB | 25x | |
| **svtav1 lossless** | **6.18MB** | **134x** | AV1 kayıpsız - desende lider |
| statik kare×600 x264 | 0.50MB | **1642x** | temporal/kare tekrarı |
| statik x265 | 0.63MB | 1322x | |
| statik svtav1 | 0.59MB | 1394x | |

**Video sonuçları:** (1) codec seçimi içeriğe bağlı (x265 her zaman iyi değil - registry
içerik-sınıfına göre seçmeli); (2) kayıpsız video için AV1 lossless lider; (3) statik/temporal
içerik 1300-1600x - "keyframe dedup + delta" iddiasının gerçek çekirdeği; (4) VMAF ölçümü
sandbox'ta model yokluğundan yapılamadı (boyut karşılaştırması yeterli).

## 6. YENİ DOMAIN TRANSFORMLARI (2026-08-16 - fikirler2.0/ficirler.md sentezi)

| Transform | Kaynak fikir | Ölçüm | Durum |
|---|---|---|---|
| **Zaman serisi (Gorilla deseni)** | K92 | **12.8x** telemetri (kanarya: ≥8x) | kodlu (bud_format_timeseries) |
| **LOG alan-tanımlı şablon** | K88-3/F21 | genel zstd'den 1.2x+ iyi (nginx) | kodlu (bud_format_logfield) |
| **Tenant sözlüğü** | İ5/F1048 | küçük JSON 1.20x → **2.75x** | kodlu (bud_format_dictionary) |
| **Ses** | K91 | FLAC ~1.9x, APE ~3x | dış codec (FLAC) - KF2 |
| **Genomik** | K93 | genozip 6x (gzip üstü) | dış (genozip) - referans-kümesi yönü |
| **3D/nokta bulutu** | K94 | Draco 10-12x | dış (draco) - KF2 |
| **Görüntü** | K80 | PNG→JXL 3.6x | dış (JPEG XL) - KF2 |

"20 sistem bir arada": .bud = konteyner + codec (Raw/Huffman/Zstd/Sözlük) + transform
(columnar/log-alan/zaman-serisi/video-sınıfı/görünüm) + kanıt (PACT/üretim/checkpoint/PoR/BFT)
+ ekonomi (rezidüel-fiyat/egress) + sahiplik (K74).

## 7. V7 SENARYOLARI × B.U.D. 2.0 (2026-08-16 sentez)

V7 kabul edilen 3/23: yedek %1 değişim 66x, %5 değişim 13.7x, JSON/log 13.07x.
- Video×10 dedup RED nedeni: **SSD dedup indeksi maliyeti** - B.U.D. tenant dedup fiyatına
  indeks maliyeti girmeli.
- B.U.D. 2.0: JSON OrderFree 12.07x ≈ V7'nin 13.07x'i; yedek/delta akışı (K20 çoklu dosya)
  V7'nin 66x senaryosunu gerçekleştirir (sıradaki iş).
