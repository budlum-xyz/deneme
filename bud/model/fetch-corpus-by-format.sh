#!/bin/bash
# Corpus parça parça fetch - by_format kararı
# GitHub limiti 100MB+ aşıyor, format bazlı parça

set -e
echo "== B.U.D. 2.0 corpus by_format fetch =="

FORMATS="json csv log text wav parquet genomic xlsx mp3 mp4 jpeg png zip epub pptx pdf docx"

for fmt in $FORMATS; do
  echo "--- Fetching $fmt ---"
  # Örnek: python3 model/fetch-corpus.py --only $fmt --small
  # Gerçekte: gs://budlum-corpus/$fmt/*
  # Burada stub: corpus/$fmt.json varsa measure
  if [ -f "../../corpus/${fmt}.json" ]; then
    echo "Found corpus/${fmt}.json"
  else
    echo "No corpus/${fmt}.json, skip (would fetch)"
  fi
  # Measure
  if [ -f "../scripts/measure-${fmt}.py" ]; then
    python3 ../scripts/measure-${fmt}.py --only $fmt 2>&1 | tail -n 5
  fi
done

echo "Hepsi parça parça denendi - by_format kararı"
