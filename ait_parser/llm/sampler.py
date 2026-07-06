"""
Stratified sampler for LLM evaluation.

Problem
-------
The test split (wheeler, wilson, santos) contains ~1.38M alerts. They are
wildly imbalanced:
    - dirb dominates attack labels (hundreds of thousands)
    - reverse_shell has ~66, webshell ~68, service_stop ~7
A naive random sample of a few thousand would be almost entirely dirb +
benign and contain perhaps one reverse shell. That makes per-phase
evaluation impossible for the rare-but-critical phases.

Solution
--------
Stratified sampling with per-phase quotas:
    - Take ALL available instances of rare phases (below a "take-all"
      threshold)
    - Cap common phases at a maximum quota
    - Add a benign set sized to roughly balance the attack set

Two profiles are provided:
    full  (~4,800 alerts) — statistically generous; use with GPU inference
    small (~2,000 alerts) — reduced caps for tractable CPU inference

The rare phases are IDENTICAL across profiles — only the common-phase and
benign caps are reduced in the small profile. This preserves per-phase
precision/recall on the rare-but-critical phases (which carry the
dissertation's core argument) while roughly halving CPU inference time.

The sample is drawn ONLY from the test scenarios. Train scenarios are never
touched, preserving the integrity of the scenario-level split.

Determinism
-----------
A fixed random seed makes the sample reproducible. Re-running produces the
identical sample, which matters for reproducibility and for comparing
LLM-only vs LLM+RAG on exactly the same alerts.

python3 ait_parser/llm/sampler.py \
    --input data/processed/alerts_labeled.jsonl \
    --output data/processed/sample_2k.jsonl \
    --profile small \
    --seed 42
"""

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

# Reuse the canonical split definition from the baseline stage
sys.path.insert(0, str(Path(__file__).parent.parent))
from baselines.splits import TEST_SCENARIOS


QUOTA_PROFILES = {
    "full": {
        "phases": {
            "reverse_shell":        {"mode": "take_all"},
            "webshell":             {"mode": "take_all"},
            "service_stop":         {"mode": "take_all"},
            "privilege_escalation": {"mode": "take_all"},
            "network_scans":        {"mode": "cap", "max": 400},
            "service_scans":        {"mode": "cap", "max": 400},
            "cracking":             {"mode": "cap", "max": 500},
            "dnsteal":              {"mode": "cap", "max": 500},
            "wpscan":               {"mode": "cap", "max": 500},
            "dirb":                 {"mode": "cap", "max": 800},
        },
        "benign": 1500,
    },
    "small": {
        "phases": {
            # Rare phases — unchanged, take everything
            "reverse_shell":        {"mode": "take_all"},
            "webshell":             {"mode": "take_all"},
            "service_stop":         {"mode": "take_all"},
            "privilege_escalation": {"mode": "take_all"},
            # Common phases — reduced caps for CPU tractability
            "network_scans":        {"mode": "cap", "max": 150},
            "service_scans":        {"mode": "cap", "max": 150},
            "cracking":             {"mode": "cap", "max": 200},
            "dnsteal":              {"mode": "cap", "max": 200},
            "wpscan":               {"mode": "cap", "max": 200},
            "dirb":                 {"mode": "cap", "max": 250},
        },
        "benign": 600,
    },
}


def iter_test_alerts(labeled_path: Path):
    """Yield only alerts whose scenario is in the test split."""
    with labeled_path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            if alert.get("scenario") in TEST_SCENARIOS:
                yield alert


def sample(labeled_path: Path, profile: str = "small", seed: int = 42) -> Dict:
    """Draw the stratified sample. Returns dict with samples + provenance."""
    if profile not in QUOTA_PROFILES:
        raise ValueError(f"Unknown profile '{profile}'. "
                         f"Choose from {list(QUOTA_PROFILES)}")
    phase_quotas = QUOTA_PROFILES[profile]["phases"]
    benign_quota = QUOTA_PROFILES[profile]["benign"]

    rng = random.Random(seed)

    # First pass: bucket all test alerts by (is_attack, attack_phase)
    by_phase: Dict[str, List[dict]] = defaultdict(list)
    benign: List[dict] = []

    print(f"Pass 1: bucketing test-split alerts by phase "
          f"(profile='{profile}')...", file=sys.stderr)
    n_seen = 0
    for alert in iter_test_alerts(labeled_path):
        n_seen += 1
        if alert.get("is_attack"):
            phase = alert.get("attack_phase") or "unknown"
            by_phase[phase].append(alert)
        else:
            benign.append(alert)
        if n_seen % 200_000 == 0:
            print(f"  ... scanned {n_seen:,} test alerts", file=sys.stderr)

    print(f"  Total test alerts scanned: {n_seen:,}", file=sys.stderr)
    print(f"  Benign pool: {len(benign):,}", file=sys.stderr)
    for phase in sorted(by_phase):
        print(f"  {phase}: {len(by_phase[phase]):,} available", file=sys.stderr)

    # Second pass: apply quotas
    selected: List[dict] = []
    provenance: Dict[str, int] = {}

    for phase, quota in phase_quotas.items():
        pool = by_phase.get(phase, [])
        if not pool:
            provenance[phase] = 0
            continue
        if quota["mode"] == "take_all":
            picked = list(pool)
        else:  # cap
            if len(pool) <= quota["max"]:
                picked = list(pool)
            else:
                picked = rng.sample(pool, quota["max"])
        selected.extend(picked)
        provenance[phase] = len(picked)

    # Benign
    if len(benign) <= benign_quota:
        benign_picked = list(benign)
    else:
        benign_picked = rng.sample(benign, benign_quota)
    selected.extend(benign_picked)
    provenance["benign"] = len(benign_picked)

    # Shuffle so phases are interleaved (avoids ordering artifacts in inference)
    rng.shuffle(selected)

    return {
        "profile": profile,
        "seed": seed,
        "total_selected": len(selected),
        "provenance": provenance,
        "test_scenarios": sorted(TEST_SCENARIOS),
        "alerts": selected,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, type=Path,
                    help="Path to alerts_labeled.jsonl")
    ap.add_argument("--output", required=True, type=Path,
                    help="Path to write the sampled alerts (JSONL)")
    ap.add_argument("--stats-output", type=Path, default=None,
                    help="Path to write sample statistics JSON "
                         "(defaults next to --output)")
    ap.add_argument("--profile", choices=list(QUOTA_PROFILES), default="small",
                    help="Sampling profile: 'full' (~4.8k, GPU) or "
                         "'small' (~2k, CPU). Default: small")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    if not args.input.exists():
        print(f"ERROR: input not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    result = sample(args.input, profile=args.profile, seed=args.seed)

    # Write sampled alerts
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w") as f:
        for alert in result["alerts"]:
            f.write(json.dumps(alert, default=str) + "\n")

    # Write stats (without the full alert bodies)
    stats = {k: v for k, v in result.items() if k != "alerts"}
    stats_path = args.stats_output or args.output.with_suffix(".stats.json")
    stats_path.write_text(json.dumps(stats, indent=2, default=str))

    print("\n=== Sample Summary ===", file=sys.stderr)
    print(json.dumps(stats, indent=2), file=sys.stderr)
    print(f"\nWrote {result['total_selected']:,} alerts to {args.output}",
          file=sys.stderr)
    print(f"Wrote stats to {stats_path}", file=sys.stderr)


if __name__ == "__main__":
    main()