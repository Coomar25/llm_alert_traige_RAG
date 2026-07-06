import "./globals.css";
import Nav from "./Nav";

export const metadata = {
  title: "LLM Alert Triage — Viva Demo",
  description:
    "LLM-based intelligent alert triage and prioritisation for backend microservice security operations (AIT-ADS).",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <Nav />
        {children}
      </body>
    </html>
  );
}
