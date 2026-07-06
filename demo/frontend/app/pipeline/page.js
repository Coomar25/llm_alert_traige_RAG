"use client";

import { useEffect, useState } from "react";
import { getOverview } from "@/lib/api";

const STAGES = [
  {
    n: 1,
    title: "Parse & normalise",
    body:
      "2.65M alerts from three IDS (Wazuh HIDS, Suricata NIDS, AMiner) in three JSON schemas are normalised into one unified schema, with severity reconciled onto a single 1–5 scale.",
  },
  {
    n: 2,
    title: "Ground-truth labelling",
    body:
      "Each alert is labelled attack vs. benign and tagged with its attack phase, derived from the AIT-ADS attack timelines — the reference for scoring.",
  },
  {
    n: 3,
    title: "Knowledge base",
    body:
      "Runbooks, MITRE ATT&CK techniques and CVEs are chunked, embedded (all-MiniLM-L6-v2) and stored in ChromaDB for source-balanced retrieval.",
  },
  {
    n: 4,
    title: "Triage & evaluate",
    body:
      "A local LLM classifies each held-out alert. LLM+RAG first retrieves the top-k KB entries. Both are scored on identical precision/recall/F1 metrics.",
  },
];

export default function Pipeline() {
  const [ov, setOv] = useState(null);
  useEffect(() => {
    getOverview().then(setOv).catch(() => {});
  }, []);

  return (
    <div className="page">
      <h1 className="title">The pipeline</h1>
      <p className="subtitle">
        End-to-end, from raw multi-IDS alerts to a scored triage decision. The
        demo evaluates the final stage; the earlier stages produce the cached
        data it runs on.
      </p>

      <div className="flow">
        {STAGES.map((s, i) => (
          <div key={s.n} style={{ display: "contents" }}>
            <div className="stage">
              <div className="n">{s.n}</div>
              <h3>{s.title}</h3>
              <p>{s.body}</p>
            </div>
            {i < STAGES.length - 1 && <div className="arrowcol">→</div>}
          </div>
        ))}
      </div>

      <div className="section-label">Experimental setup</div>
      <div className="grid cols-3">
        <div className="card stat">
          <div className="k">Dataset</div>
          <div className="v" style={{ fontSize: 22 }}>
            AIT-ADS
          </div>
          <div className="sub">Zenodo 8263181 · CC-BY 4.0 · 8 attack scenarios</div>
        </div>
        <div className="card stat">
          <div className="k">Model</div>
          <div className="v" style={{ fontSize: 22 }}>
            {ov ? ov.config.model : "llama3.1:8b"}
          </div>
          <div className="sub">Run locally via Ollama · no cloud, no API</div>
        </div>
        <div className="card stat">
          <div className="k">Knowledge base</div>
          <div className="v" style={{ fontSize: 22 }}>
            {ov ? ov.config.kb_document_count.toLocaleString() : "—"} docs
          </div>
          <div className="sub">Runbooks · MITRE ATT&CK · CVEs · ChromaDB</div>
        </div>
      </div>

      <div className="section-label">Why these choices (viva notes)</div>
      <div className="card">
        <ul style={{ lineHeight: 1.7, margin: 0, paddingLeft: 20 }}>
          <li>
            <b>Local Llama, not a frontier API</b> — reproducibility, zero cost,
            and data sovereignty for sensitive security logs.
          </li>
          <li>
            <b>all-MiniLM-L6-v2 embeddings</b> — 384-dim, CPU-friendly, a
            standard, defensible RAG baseline.
          </li>
          <li>
            <b>Source-balanced retrieval</b> — CVEs outnumber runbooks ~4600:1,
            so naive top-k floods the prompt with CVE noise; balancing guarantees
            a runbook + a technique are always seen.
          </li>
          <li>
            <b>No ground-truth leakage</b> — retrieval queries use only
            observable alert content, never the label.
          </li>
        </ul>
      </div>
    </div>
  );
}
