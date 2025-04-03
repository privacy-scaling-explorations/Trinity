/// <reference types="node" />
import { defineConfig } from "tsup";
import { resolve } from "path";
import { copyFileSync } from "fs";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  onSuccess: async () => {
    // Copy WASM files to dist folder using process.cwd()
    copyFileSync(
      resolve(process.cwd(), "src/wasm/trinity_bg.wasm"),
      resolve(process.cwd(), "dist/trinity_bg.wasm")
    );
  },
});
