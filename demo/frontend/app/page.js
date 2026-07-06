"use client";

import { useEffect, useState } from "react";
import { getOverview, getPhases, pct, secs, PALETTE } from "@/lib/api";
import PhaseChart from "./PhaseChart";

function Stat({ k, v, sub, delta }) {
  return (
    <div className="card stat">
      <div className="k">{k}</div>
      <div className="v">{v}</div>
      {sub && <div className="sub">{sub}</div>}
      {delta}
    </div>
  );
}

function best(a, b, higherBetter = true) {
  if (a == null || b == null) return [false, false];
  if (a === b) return [false, false];
  const aWins = higherBetter ? a > b : a < b;
  return [aWins, !aWins];
}

export default function Overview() {
  const [ov, setOv] = useState(null);
  const [phases, setPhases] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    Promise.all([getOverview(), getPhases()])
      .then(([o, p]) => {
        setOv(o);
        setPhases(p);
      })
      .catch((e) => setErr(String(e)));
  }, []);

  if (err)
    return (
      <div className="page">
        <div className="errbox">
          Could not reach the API ({err}).<br />
          Start the backend: <code>demo/.venv/bin/uvicorn backend.main:app
          --app-dir demo --port 8077</code>
        </div>
      </div>
    );
  if (!ov || !phases) return <div className="page loading">Loading…</div>;

  const A = ov.pipelines.llm_only;
  const B = ov.pipelines.llm_rag;
  const eff = ov.rag_effect;

  const rows = [
    { k: "Precision", a: A.precision, b: B.precision, hb: true },
    { k: "Recall", a: A.recall, b: B.recall, hb: true },
    { k: "F1 score", a: A.f1, b: B.f1, hb: true },
    { k: "False-positive rate", a: A.fpr, b: B.fpr, hb: false },
  ];

  return (
    <div className="page">
      <h1 className="title">Does retrieval-augmentation help LLM alert triage?</h1>
      <p className="subtitle">
        Two pipelines classify the same {ov.config.n_alerts} held-out security
        alerts from {ov.config.dataset} as attack vs. benign, using{" "}
        <b>{ov.config.model}</b> locally. The only difference: LLM+RAG first
        retrieves the top-{ov.config.top_k} most relevant entries from a{" "}
        {ov.config.kb_document_count.toLocaleString()}-document knowledge base
        (runbooks · MITRE ATT&CK · CVEs) and injects them into the prompt.
      </p>

      <div className="grid cols-4">
        <Stat
          k="F1 — LLM-only"
          v={pct(A.f1)}
          sub={`${pct(A.precision)} precision · ${pct(A.recall)} recall`}
        />
        <Stat
          k="F1 — LLM + RAG"
          v={pct(B.f1)}
          sub={`${pct(B.precision)} precision · ${pct(B.recall)} recall`}
          delta={
            <div className={"sub delta " + (eff.delta_f1 >= 0 ? "up" : "down")}>
              {eff.delta_f1 >= 0 ? "▲" : "▼"} {pct(Math.abs(eff.delta_f1))} F1
              vs LLM-only
            </div>
          }
        />
        <Stat
          k="False positives cut"
          v={pct(Math.abs(eff.delta_fpr))}
          sub="RAG lowered the false-positive rate"
          delta={<div className="sub delta up">▼ fewer false alarms</div>}
        />
        <Stat
          k="Latency cost"
          v={`${(B.mean_latency_ms / A.mean_latency_ms).toFixed(1)}×`}
          sub={`${secs(A.mean_latency_ms)} → ${secs(B.mean_latency_ms)} per alert`}
          delta={<div className="sub delta down">▲ slower with retrieval</div>}
        />
      </div>

      <div className="section-label">Headline comparison</div>
      <div className="grid cols-2">
        <div className="card">
          <table className="cmp">
            <thead>
              <tr>
                <th>Metric</th>
                <th>
                  <span className="swatch" style={{ background: PALETTE.llmOnly }} />
                  LLM-only
                </th>
                <th>
                  <span className="swatch" style={{ background: PALETTE.llmRag }} />
                  LLM + RAG
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const [aw, bw] = best(r.a, r.b, r.hb);
                return (
                  <tr key={r.k}>
                    <td>{r.k}</td>
                    <td className={aw ? "best" : ""}>{pct(r.a)}</td>
                    <td className={bw ? "best" : ""}>{pct(r.b)}</td>
                  </tr>
                );
              })}
              <tr>
                <td>Mean latency / alert</td>
                <td className="best">{secs(A.mean_latency_ms)}</td>
                <td>{secs(B.mean_latency_ms)}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="card">
          <div className="section-label" style={{ margin: "0 0 12px" }}>
            The key finding
          </div>
          <div className="callout">
            RAG made the model <b>more precise and far less trigger-happy</b> —
            precision rose to {pct(B.precision)} and false positives fell by{" "}
            {pct(Math.abs(eff.delta_fpr))}. But that caution came at a cost:{" "}
            <b>recall dropped {pct(Math.abs(eff.delta_recall))}</b> and F1 fell,
            because the retrieved context led the model to dismiss some genuine
            attack steps. Retrieval improved {eff.phases_improved} attack phases
            and worsened {eff.phases_worsened}.
          </div>
          <div className="kv" style={{ marginTop: 16 }}>
            <span>
              <b>{ov.story_counts.rag_fixed}</b> alerts RAG fixed
            </span>
            <span>·</span>
            <span>
              <b>{ov.story_counts.rag_broke}</b> alerts RAG broke
            </span>
            <span>·</span>
            <span>
              <b>{ov.story_counts.both_correct}</b> both correct
            </span>
          </div>
        </div>
      </div>

      <div className="section-label">Where RAG changed the outcome</div>
      <div className="card">
        <PhaseChart phases={phases} />
        <p style={{ fontSize: 13, color: "#898781", marginTop: 8 }}>
          ▼ marks a phase where retrieval reduced recall. No phase improved;
          six regressed. Explore individual alerts in the Triage Explorer.
        </p>
      </div>
    </div>
  );
}
