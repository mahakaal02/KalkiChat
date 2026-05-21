import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'KalkiChat Admin',
  description: 'Internal administration console',
  robots: { index: false, follow: false, nocache: true },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>{children}</body>
    </html>
  );
}
