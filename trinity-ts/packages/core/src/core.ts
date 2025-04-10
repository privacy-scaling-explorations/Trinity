import init_wasm, {
  TrinityWasmSetup,
  TrinityEvaluator,
  TrinityGarbler,
  parse_circuit,
  CircuitWrapper,
  WasmCommitment,
} from "./wasm/trinity";

let isInitialized = false;

export { TrinityWasmSetup, TrinityEvaluator, TrinityGarbler, parse_circuit };

export type { CircuitWrapper, WasmCommitment };

export interface TrinityModule {
  parseCircuit: (
    circuitText: string,
    evaluator_input_size: number,
    garbler_input_size: number,
    output_size: number
  ) => CircuitWrapper;

  TrinityWasmSetup: (mode: "Plain" | "Halo2") => TrinityWasmSetup;

  TrinityEvaluator: (
    setup: TrinityWasmSetup,
    evaluator_input: Uint8Array
  ) => TrinityEvaluator;

  TrinityGarbler: (
    evaluator_commitment: string,
    setup: TrinityWasmSetup,
    garbler_input: Uint8Array,
    circuit: CircuitWrapper
  ) => TrinityGarbler;
}

/**
 * Initialize the WASM module
 */
export async function initTrinity(): Promise<TrinityModule> {
  if (!isInitialized) {
    // For ESM builds
    try {
      // For browsers/bundlers that support import.meta
      const wasmUrl = new URL("./trinity_bg.wasm", import.meta.url).href;
      await init_wasm(wasmUrl);
      isInitialized = true;
    } catch (e) {
      // Fallback for environments like Node.js
      await init_wasm();
      isInitialized = true;
    }
  }

  return {
    parseCircuit: (
      circuitText: string,
      evaluator_input_size: number,
      garbler_input_size: number,
      output_size: number
    ) => {
      if (!isInitialized) throw new Error("Trinity WASM not initialized");
      return parse_circuit(
        circuitText,
        evaluator_input_size,
        garbler_input_size,
        output_size
      );
    },

    TrinityWasmSetup: function (mode: "Plain" | "Halo2") {
      if (!isInitialized) throw new Error("Trinity WASM not initialized");
      return new TrinityWasmSetup(mode);
    },

    TrinityEvaluator: function (
      setup: TrinityWasmSetup,
      evaluator_input: Uint8Array
    ) {
      if (!isInitialized) throw new Error("Trinity WASM not initialized");
      return new TrinityEvaluator(setup, evaluator_input);
    },

    TrinityGarbler: function (
      evaluator_commitment: string,
      setup: TrinityWasmSetup,
      garbler_input: Uint8Array,
      circuit: CircuitWrapper
    ) {
      if (!isInitialized) throw new Error("Trinity WASM not initialized");
      return new TrinityGarbler(
        evaluator_commitment,
        setup,
        garbler_input,
        circuit
      );
    },
  };
}

export default {
  initTrinity,
  parse_circuit,
  TrinityWasmSetup,
  TrinityEvaluator,
  TrinityGarbler,
};
