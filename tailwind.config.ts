import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        foreground: "var(--foreground)",
        surface: {
          DEFAULT: "#0f1117",
          elevated: "#161b27",
          border: "#1e2535",
        },
        accent: {
          green: "#00ff88",
          red: "#ff4757",
          yellow: "#ffa502",
          blue: "#3d9eff",
          purple: "#a55eea",
        },
        risk: {
          low: "#00ff88",
          medium: "#ffa502",
          high: "#ff6b35",
          critical: "#ff4757",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
        sans: ["Inter", "system-ui", "sans-serif"],
      },
    },
  },
  plugins: [],
};

export default config;
