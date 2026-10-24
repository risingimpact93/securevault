export default function Logo({ className = "brand-mark" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 256 256" aria-hidden="true">
      <defs>
        <linearGradient id="khShield" x1="40" y1="16" x2="210" y2="240" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#2a6b57" />
          <stop offset="1" stopColor="#14352c" />
        </linearGradient>
        <linearGradient id="khGold" x1="96" y1="72" x2="160" y2="188" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#f0d078" />
          <stop offset="1" stopColor="#c4921a" />
        </linearGradient>
      </defs>
      <path
        d="M48 70c0-22 24-42 80-42s80 20 80 42c0 58-28 118-80 160C76 188 48 128 48 70z"
        fill="url(#khShield)"
        stroke="#c9a227"
        strokeWidth="8"
        strokeLinejoin="round"
      />
      <circle cx="128" cy="104" r="26" fill="none" stroke="url(#khGold)" strokeWidth="14" />
      <path
        d="M118 124h20c2 0 4 1.6 4 4.2L136 182c0 4.4-3.6 8-8 8h0c-4.4 0-8-3.6-8-8l-6-53.8c0-2.6 2-4.2 4-4.2z"
        fill="url(#khGold)"
      />
    </svg>
  );
}
