import './globals.css';
import { Inter, JetBrains_Mono, Fira_Code } from 'next/font/google';
import Providers from '../components/Providers';
import LayoutShell from '../components/LayoutShell';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-geist',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  weight: ['400', '500', '600'],
  display: 'swap',
});

const firaCode = Fira_Code({
  subsets: ['latin'],
  variable: '--font-fira',
  weight: ['400', '500'],
  display: 'swap',
});

export const metadata = {
  title: 'ALIE — API Lifecycle Intelligence Engine',
  description: 'Enterprise security operations center for API threat detection, zombie API discovery, and TrapNet active defense.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable} ${firaCode.variable}`}
      suppressHydrationWarning
    >
      <body className="font-sans antialiased">
        <Providers>
          <LayoutShell>{children}</LayoutShell>
        </Providers>
      </body>
    </html>
  );
}
