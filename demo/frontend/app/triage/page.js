"use client";

import { useEffect, useMemo, useState } from "react";
import {
  getAlerts,
  getAlert,
  pct,
  secs,
  PALETTE,
  TAG_META,
} from "@/lib/api";

const SRC_COLOR = {
  runbook: "#4a3aa7",
  mitre: "#eb6834",
  cve: "#52514e",
  unknown: "#898781",
};
const SRC_LABEL = {
  runbook: "RUNBOOK",
  mitre: "MITRE ATT&CK",
  cve: "CVE",
};

const FILTERS = [
  { key: "all", label: "All" },
  { key: "rag_broke", label: "RAG broke" },
  { key: "rag_fixed", label: "RAG fixed" },
  { key: "both_correct", label: "Both correct" },
  { key: "both_wrong", label: "Both wrong" },
];

function Verdict({ title, color, pred, correct }) {
  const isAttack = pred.predicted_is_attack;
  return (
    <div className="verdict">
      <div className="head" style={{ background: color }}>
        <span>{title}</span>
        <span className={"result-flag " + (correct ? "ok" : "no")}>
          {correct ? "✓ correct" : "✗ wrong"}
        </span>
      </div>
      <div className="body">
        <span className={"badge " + (isAttack ? "attack" : "benign")}>
          {isAttack ? "⚠ ATTACK" : "✓ benign"}
        </span>
        <div className="kv">
          {pred.predicted_attack_phase && (
            <span>
              phase: <b>{pred.predicted_attack_phase}</b>
            </span>
          )}
          <span>
            confidence: <b>{pred.confidence != null ? pct(pred.confidence) : "—"}</b>
          </span>
          <span>
            latency: <b>{secs(pred.latency_ms)}</b>
          </span>
        </div>
        <div className="explain">“{pred.explanation}”</div>
      </div>
    </div>
  );
}

function RetrievedDoc({ d }) {
  const color = SRC_COLOR[d.source] || SRC_COLOR.unknown;
  const [full, setFull] = useState(false);
  const body = full && d.text_full ? d.text_full : d.text;
  return (
    <div className="doc">
      <div className="dhead">
        <span className="srctag" style={{ background: color }}>
          {SRC_LABEL[d.source] || d.source}
        </span>
        <span className="dtitle">
          {[d.ident, d.title].filter(Boolean).join(" · ") || "(untitled)"}
        </span>
        {d.similarity != null && (
          <span className="simbar" title={`similarity ${d.similarity}`}>
            <i style={{ width: `${Math.round(d.similarity * 100)}%` }} />
          </span>
        )}
      </div>
      {body && <div className="dtext">{body}</div>}
      {d.truncated && (
        <button className="morebtn" onClick={() => setFull((v) => !v)}>
          {full ? "▲ show injected snippet only" : "▼ show full KB entry"}
        </button>
      )}
    </div>
  );
}

export default function Triage() {
  const [list, setList] = useState(null);
  const [filter, setFilter] = useState("rag_broke");
  const [selId, setSelId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    getAlerts()
      .then((l) => setList(l))
      .catch((e) => setErr(String(e)));
  }, []);

  const filtered = useMemo(() => {
    if (!list) return [];
    return filter === "all" ? list : list.filter((a) => a.tag === filter);
  }, [list, filter]);

  // Auto-select the first alert of the current filter.
  useEffect(() => {
    if (filtered.length && !filtered.find((a) => a.alert_id === selId)) {
      setSelId(filtered[0].alert_id);
    }
  }, [filtered, selId]);

  useEffect(() => {
    if (!selId) return;
    setDetail(null);
    getAlert(selId)
      .then(setDetail)
      .catch((e) => setErr(String(e)));
  }, [selId]);

  if (err)
    return (
      <div className="page">
        <div className="errbox">Could not reach the API ({err}).</div>
      </div>
    );
  if (!list) return <div className="page loading">Loading…</div>;

  return (
    <div className="page wide">
      <h1 className="title">Triage Explorer</h1>
      <p className="subtitle">
        Every held-out alert, with the ground-truth label and both pipelines&rsquo;
        verdicts side by side — plus the exact knowledge-base context RAG
        retrieved. Filter to <b>RAG broke</b> to see where retrieval turned a
        correct call into a miss.
      </p>

      <div className="triage">
        {/* -------- left: alert list -------- */}
        <div className="alist">
          <div className="filters">
            {FILTERS.map((f) => {
              const n =
                f.key === "all"
                  ? list.length
                  : list.filter((a) => a.tag === f.key).length;
              return (
                <button
                  key={f.key}
                  className={"chip" + (filter === f.key ? " on" : "")}
                  onClick={() => setFilter(f.key)}
                >
                  {f.label} · {n}
                </button>
              );
            })}
          </div>
          <div className="arows">
            {filtered.map((a) => {
              const tm = TAG_META[a.tag];
              return (
                <div
                  key={a.alert_id}
                  className={"arow" + (a.alert_id === selId ? " sel" : "")}
                  onClick={() => setSelId(a.alert_id)}
                >
                  <div className="top">
                    <span
                      className="tagdot"
                      style={{ background: tm.color }}
                    >
                      {tm.label}
                    </span>
                    <span
                      style={{
                        fontSize: 12,
                        fontWeight: 700,
                        color: a.ground_truth.is_attack
                          ? PALETTE.bad
                          : PALETTE.good,
                      }}
                    >
                      {a.ground_truth.is_attack
                        ? a.ground_truth.attack_phase || "attack"
                        : "benign"}
                    </span>
                  </div>
                  <div className="desc">
                    {a.description || "(no description)"}
                  </div>
                  <div className="meta">
                    {a.scenario} · {a.log_source}
                  </div>
                </div>
              );
            })}
            {!filtered.length && (
              <div className="loading">No alerts in this group.</div>
            )}
          </div>
        </div>

        {/* -------- right: detail -------- */}
        <div>
          {!detail ? (
            <div className="card loading">Loading alert…</div>
          ) : (
            <>
              {/* alert card */}
              <div className="card" style={{ marginBottom: 18 }}>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: 12,
                  }}
                >
                  <div className="section-label" style={{ margin: 0 }}>
                    Incoming alert
                  </div>
                  <span
                    className="badge"
                    style={{
                      background: detail.ground_truth.is_attack
                        ? "#fbe9e9"
                        : "#e9f6ec",
                      color: detail.ground_truth.is_attack
                        ? PALETTE.bad
                        : PALETTE.good,
                    }}
                  >
                    ground truth:{" "}
                    {detail.ground_truth.is_attack
                      ? `ATTACK · ${detail.ground_truth.attack_phase}`
                      : "benign"}
                  </span>
                </div>
                <dl className="fields">
                  <dt>description</dt>
                  <dd>{detail.display.description || "—"}</dd>
                  <dt>scenario</dt>
                  <dd>{detail.display.scenario || "—"}</dd>
                  <dt>source</dt>
                  <dd>
                    {detail.display.log_source} · {detail.display.program_name || "—"}
                  </dd>
                  <dt>host</dt>
                  <dd>
                    {detail.display.host || "—"} ({detail.display.host_ip || "—"})
                  </dd>
                  <dt>network</dt>
                  <dd>
                    {detail.display.src_ip || "—"}
                    {detail.display.src_port ? ":" + detail.display.src_port : ""} →{" "}
                    {detail.display.dst_ip || "—"}
                    {detail.display.dst_port ? ":" + detail.display.dst_port : ""}{" "}
                    {detail.display.protocol || ""}
                  </dd>
                  <dt>severity (1–5)</dt>
                  <dd>{detail.display.severity_norm ?? "—"}</dd>
                  <dt>MITRE</dt>
                  <dd>
                    {(detail.display.mitre_techniques &&
                      detail.display.mitre_techniques.length &&
                      detail.display.mitre_techniques.join(", ")) ||
                      "—"}
                  </dd>
                </dl>
                {detail.display.raw_message && (
                  <div className="raw">{detail.display.raw_message}</div>
                )}
              </div>

              {/* verdicts */}
              <div className="section-label" style={{ marginTop: 0 }}>
                Pipeline verdicts
              </div>
              <div className="verdicts">
                <Verdict
                  title="LLM-only"
                  color={PALETTE.llmOnly}
                  pred={detail.llm_only}
                  correct={detail.llm_only.correct}
                />
                <Verdict
                  title="LLM + RAG"
                  color={PALETTE.llmRag}
                  pred={detail.llm_rag}
                  correct={detail.llm_rag.correct}
                />
              </div>

              {/* retrieved context */}
              <div className="section-label">
                What RAG retrieved{" "}
                <span
                  style={{
                    color: "#898781",
                    fontWeight: 500,
                    textTransform: "none",
                    letterSpacing: 0,
                  }}
                >
                  · top-3 KB entries injected into the LLM+RAG prompt, trimmed
                  to 320 chars each ({secs(detail.llm_rag.retrieval_ms)} to
                  retrieve)
                </span>
              </div>
              <div className="card">
                {detail.llm_rag.retrieved.length ? (
                  detail.llm_rag.retrieved.map((d, i) => (
                    <RetrievedDoc key={i} d={d} />
                  ))
                ) : (
                  <div className="loading">
                    No knowledge-base entries were retrieved for this alert.
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
