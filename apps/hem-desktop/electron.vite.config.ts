import react from '@vitejs/plugin-react';
import { defineConfig, externalizeDepsPlugin } from 'electron-vite';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — no bundled types
import stylexPostcss from '@stylexjs/postcss-plugin';

const isDev = process.env.NODE_ENV !== 'production';

export default defineConfig({
  main: {
    plugins: [externalizeDepsPlugin()],
  },
  preload: {
    plugins: [externalizeDepsPlugin()],
    build: {
      rollupOptions: {
        output: { format: 'cjs' },
      },
    },
  },
  renderer: {
    plugins: [
      react({
        babel: {
          plugins: [
            [
              '@stylexjs/babel-plugin',
              {
                dev: isDev,
                runtimeInjection: false,
                treeshakeCompensation: true,
                unstable_moduleResolution: { type: 'commonJS' },
              },
            ],
          ],
        },
      }),
    ],
    css: {
      postcss: {
        plugins: [
          stylexPostcss({
            include: ['src/renderer/**/*.{ts,tsx}'],
            useCSSLayers: true,
            babelConfig: {
              babelrc: false,
              parserOpts: { plugins: ['typescript', 'jsx'] },
              plugins: [
                [
                  '@stylexjs/babel-plugin',
                  {
                    dev: isDev,
                    runtimeInjection: false,
                    treeshakeCompensation: true,
                    unstable_moduleResolution: { type: 'commonJS' },
                  },
                ],
              ],
            },
          }),
        ],
      },
    },
  },
});
