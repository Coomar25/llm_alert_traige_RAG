"use client";

import { useState } from "react";
import { PALETTE, pct } from "@/lib/api";

// Horizontal grouped bars: per attack phase, recall for LLM-only vs LLM+RAG.
// Follows the dataviz method: thin marks, rounded data-ends on the baseline,
// a 2px surface gap between the paired bars, direct value labels, legend for
// two series, recessive gridlines. One axis (recall 0–100%).
export default function PhaseChart({ phases }) {
  const [hover, setHover] = useState(null);

  const labelW = 150;
  const plotW = 460;
  const rowH = 46;
  const barH = 15;
  const gap = 2; // surface gap between paired bars
  const top = 34;
  const height = top + phases.length * rowH + 10;
  const width = labelW + plotW + 60;

  const x = (v) => labelW + v * plotW;
  const ticks = [0, 0.25, 0.5, 0.75, 1];

  return (
    <div>
      <div className="legend">
        <span className="item">
          <span className="swatch" style={{ background: PALETTE.llmOnly }} />
          LLM-only
        </span>
        <span className="item">
          <span className="swatch" style={{ background: PALETTE.llmRag }} />
          LLM + RAG
        </span>
        <span style={{ marginLeft: "auto", fontSize: 13, color: "#898781" }}>
          Recall per attack phase — higher is better
        </span>
      </div>

      <svg
        viewBox={`0 0 ${width} ${height}`}
        width="100%"
        role="img"
        aria-label="Recall per attack phase, LLM-only versus LLM plus RAG"
      >
        {/* gridlines + tick labels */}
        {ticks.map((t) => (
          <g key={t}>
            <line
              x1={x(t)}
              x2={x(t)}
              y1={top - 8}
              y2={height - 16}
              stroke="#e1e0d9"
              strokeWidth="1"
            />
            <text
              x={x(t)}
              y={top - 14}
              fontSize="11"
              fill="#898781"
              textAnchor="middle"
            >
              {Math.round(t * 100)}%
            </text>
          </g>
        ))}

        {phases.map((p, i) => {
          const y0 = top + i * rowH;
          const rows = [
            { key: "llm_only", v: p.llm_only, color: PALETTE.llmOnly },
            { key: "llm_rag", v: p.llm_rag, color: PALETTE.llmRag },
          ];
          return (
            <g key={p.phase}>
              <text
                x={labelW - 10}
                y={y0 + rowH / 2}
                fontSize="12.5"
                fill="#0b0b0b"
                textAnchor="end"
                dominantBaseline="middle"
              >
                {p.phase.replace(/_/g, " ")}
              </text>
              {rows.map((r, j) => {
                const by = y0 + 6 + j * (barH + gap);
                const w = Math.max(2, r.v * plotW);
                const isHover = hover === `${i}-${j}`;
                return (
                  <g
                    key={r.key}
                    onMouseEnter={() => setHover(`${i}-${j}`)}
                    onMouseLeave={() => setHover(null)}
                  >
                    {/* track */}
                    <rect
                      x={labelW}
                      y={by}
                      width={plotW}
                      height={barH}
                      fill="#f0f0ec"
                      rx="4"
                    />
                    <rect
                      x={labelW}
                      y={by}
                      width={w}
                      height={barH}
                      fill={r.color}
                      rx="4"
                      opacity={isHover ? 1 : 0.92}
                    />
                    <text
                      x={labelW + w + 8}
                      y={by + barH / 2}
                      fontSize="11.5"
                      fill="#52514e"
                      dominantBaseline="middle"
                      fontWeight={isHover ? 700 : 500}
                    >
                      {pct(r.v)}
                    </text>
                  </g>
                );
              })}
              {/* delta marker */}
              {p.delta !== 0 && (
                <text
                  x={width - 6}
                  y={y0 + rowH / 2}
                  fontSize="11"
                  fill={p.delta < 0 ? "#d03b3b" : "#006300"}
                  textAnchor="end"
                  dominantBaseline="middle"
                  fontWeight="700"
                >
                  {p.delta < 0 ? "▼" : "▲"} {pct(Math.abs(p.delta))}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
