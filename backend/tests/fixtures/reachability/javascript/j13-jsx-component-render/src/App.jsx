// JSX usage of an imported component — the only call site for
// VulnComp is the JSX element, no `VulnComp(...)` literal call.
// Analyzer must understand <VulnComp /> desugars to a runtime call.
import React from 'react';
import VulnComp from 'vuln-react-comp';

export default function App({ userInput }) {
  return (
    <div className="app">
      <h1>Hello</h1>
      <VulnComp data={userInput} />
    </div>
  );
}
