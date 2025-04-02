import { defineConfig } from "tsup";
import { copyFileSync } from "fs";
import { resolve } from "path";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  onSuccess: async () => {
    // Copy WASM files to dist folder
    copyFileSync(
      resolve(__dirname, "src/wasm/trinity_bg.wasm"),
      resolve(__dirname, "dist/trinity_bg.wasm")
    );
  },
});
