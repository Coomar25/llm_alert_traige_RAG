"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const TABS = [
  { href: "/", label: "Overview" },
  { href: "/triage", label: "Triage Explorer" },
  { href: "/pipeline", label: "Pipeline" },
];

export default function Nav() {
  const path = usePathname();
  return (
    <nav className="nav">
      <div className="brand">
        LLM <span>Triage</span>
      </div>
      {TABS.map((t) => (
        <Link
          key={t.href}
          href={t.href}
          className={"tab" + (path === t.href ? " active" : "")}
        >
          {t.label}
        </Link>
      ))}
      <div className="spacer" />
      <div className="pill">AIT-ADS · llama3.1:8b · cached</div>
    </nav>
  );
}
