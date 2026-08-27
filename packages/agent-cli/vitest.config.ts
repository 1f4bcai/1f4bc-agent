import { defineConfig } from 'vitest/config'
import { fileURLToPath } from 'node:url'

export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  test: {
    name: 'agent-cli',
    environment: 'node',
    include: ['test/**/*.test.ts'],
    // Public-export security cases create and scan complete temporary Git
    // histories. Keep a finite bound that also works on cold or shared disks.
    testTimeout: 15_000,
  },
})
