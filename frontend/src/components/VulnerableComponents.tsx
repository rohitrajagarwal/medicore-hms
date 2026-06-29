import React, { useEffect, useRef } from 'react';

// CodeQL CWE-079: dangerouslySetInnerHTML with user-controlled data
const PatientNotes: React.FC<{ notes: string }> = ({ notes }) => (
  <div dangerouslySetInnerHTML={{ __html: notes }} />  // CodeQL fires
);

// Semgrep: document.write with URL parameter
const DebugInfo: React.FC = () => {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const param = new URLSearchParams(window.location.search).get('debug') || '';
    if (ref.current) {
      ref.current.innerHTML = param;  // CodeQL CWE-079
    }
    // Semgrep: document.write
    document.write('<p>' + param + '</p>');  // Semgrep fires
    // eval on URL param
    eval(new URLSearchParams(window.location.search).get('expr') || '');  // CodeQL
  }, []);
  return <div ref={ref} />;
};

// Open redirect via window.location
const LoginCallback: React.FC = () => {
  useEffect(() => {
    const next = new URLSearchParams(window.location.search).get('next') || '/';
    window.location.href = next;  // open redirect
  }, []);
  return null;
};

// postMessage without origin check
window.addEventListener('message', (event) => {
  // CodeQL: no event.origin check before processing
  eval(event.data);  // CodeQL CWE-094
  document.getElementById('output')!.innerHTML = event.data;  // CodeQL CWE-079
});

export { PatientNotes, DebugInfo, LoginCallback };
