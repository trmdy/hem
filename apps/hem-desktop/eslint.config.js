import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['out/**', 'dist/**', 'node_modules/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      // The gRPC wire surface and IPC boundary are typed by hand; interop
      // seams occasionally need a cast through unknown.
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
);
