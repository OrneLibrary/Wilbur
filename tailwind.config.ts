import type { Config } from "tailwindcss";

export default {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}"
  ],
  theme: {
    extend: {
      colors: {
        calm: {
          50: "#f4f8ff",
          100: "#e7efff",
          600: "#3456d1"
        }
      }
    }
  },
  plugins: []
} satisfies Config;
