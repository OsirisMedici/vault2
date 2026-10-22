/** Vault 2 visual identity. Upstream behavior remains in the existing components. */
export default function Vault2Brand() {
  return (
    <span className="vault2-brand">
      <svg aria-hidden="true" viewBox="0 0 32 32" fill="none" className="vault2-mark">
        <rect x="2" y="2" width="28" height="28" rx="6" stroke="currentColor" strokeWidth="1.8" />
        <path d="M9 10.5 15 23l7.5-14H15" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        <path d="m19 13 4 8" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
      </svg>
      <span>Vault <span className="vault2-number">2</span></span>
    </span>
  );
}

export function Vault2Attribution() {
  return <footer className="vault2-attribution">Based on <a href="https://github.com/Infisical/agent-vault" target="_blank" rel="noopener noreferrer">Infisical Agent Vault</a></footer>;
}
