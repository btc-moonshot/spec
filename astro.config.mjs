// @ts-check
import { defineConfig } from 'astro/config';

// Hosted on GitHub Pages as a project site: https://btc-moonshot.github.io/spec/
export default defineConfig({
  site: 'https://btc-moonshot.github.io',
  base: '/spec',
  trailingSlash: 'ignore',
});
