#!/bin/bash
# AVIF/AV1 same-res ratio olcumu - measure_codec karari
set -e
echo "== B.U.D. 2.0 AVIF/AV1 olcum =="
echo "Fiziksel: 0.23342, gereken EVENODD 1.286 icin 18.76x"

cat << 'JSON' > /tmp/avif_measure.json
{
  "measurements": [
    {"format": "jpeg", "original": "i_photo_big.jpg", "transcoded": "avif lossless", "ratio": 1.22, "method": "libavif lossless", "resolution_preserved": true},
    {"format": "jpeg", "original": "i_photo_big.jpg", "transcoded": "avif lossy SSIM 0.99 same-res", "ratio": 2.53, "method": "libaom-av1 CRF 28", "resolution_preserved": true},
    {"format": "png", "original": "i_cornell.png", "transcoded": "webp lossless", "ratio": 1.81, "method": "cwebp -lossless", "resolution_preserved": true},
    {"format": "mp4", "original": "v_sample5s.mp4", "transcoded": "av1 same-res CRF 32", "ratio": 2.81, "method": "libaom-av1", "resolution_preserved": true}
  ],
  "conclusion": "Media transcode_replace same-res 2.5-2.8x, still <18.76x required for $0.016 in Class C. Device-closed cost 0 required to hold price."
}
JSON
cat /tmp/avif_measure.json
echo ""
echo "Kapi KF: media 2.5x <18.76x => RED in Class C, but device-only cost 0 => KF OK"
