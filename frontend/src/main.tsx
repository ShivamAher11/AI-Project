import React from "react";
import { createRoot } from "react-dom/client";

function App() {
  return (
    <main style={{ fontFamily: "system-ui", margin: "4rem auto", maxWidth: 760, padding: "0 1rem" }}>
      <h1>AI-Assisted Reverse Engineering Assistant</h1>
      <p>Static analysis dashboard scaffold. Upload and analysis views are not implemented yet.</p>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode><App /></React.StrictMode>,
);
