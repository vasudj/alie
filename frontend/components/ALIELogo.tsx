import React from 'react';

export default function ALIELogo({ className = "w-6 h-6" }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      // This locks in that crisp, professional enterprise dashboard green
      className={`${className} text-emerald-500`}
    >
      {/* The main sharp delta/A vector from the dashboard view */}
      <path d="M12 3L2 20h20L12 3z" />
      
      {/* Inner geometric accent line to give it that structural engineering depth */}
      <path d="M12 3v17" className="opacity-40" />
      <path d="M7 14h10" />
    </svg>
  );
}