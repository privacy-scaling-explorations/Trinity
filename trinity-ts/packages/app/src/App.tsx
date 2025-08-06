import {
  initTrinity,
  intToUint8Array2,
  CircuitWrapper,
  TrinityModule,
  TrinityWasmSetup,
  TrinityEvaluator,
  TrinityGarbler,
} from "@trinity_2pc/core";
import { useState, useEffect, useRef } from "react";
import "./App.css";

// Define the computation states
type ComputationState =
  | "initial" // Just loaded, nothing happened yet
  | "setup_done" // Trinity initialized, circuit loaded
  | "evaluator_committed" // Evaluator has committed to input
  | "circuit_garbled" // Garbler has created garbled circuit
  | "result_computed" // Computation complete
  | "error"; // Error state

function booleanArrayToInteger(boolArray: Uint8Array): number {
  return boolArray.reduce((acc, bit, index) => {
    return acc + (bit ? 1 : 0) * Math.pow(2, index);
  }, 0);
}

function App() {
  // State for the application
  const [trinity, setTrinity] = useState<TrinityModule | null>(null);
  const [circuit, setCircuit] = useState<CircuitWrapper | null>(null);
  const [evaluatorInput, setEvaluatorInput] = useState(4);
  const [garblerInput, setGarblerInput] = useState(6);
  const [result, setResult] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [computationState, setComputationState] =
    useState<ComputationState>("initial");

  const [setup, setSetup] = useState<TrinityWasmSetup | null>(null);
  const [evaluator, setEvaluator] = useState<TrinityEvaluator | null>(null);
  const [garbler, setGarbler] = useState<TrinityGarbler | null>(null);
  const timings = useRef<Record<string, number>>({});

  // Initialize Trinity and load circuit
  useEffect(() => {
    async function setup() {
      try {
        const t0 = performance.now();
        // Initialize Trinity
        const trinity = await initTrinity();
        const t1 = performance.now();
        timings.current["Import WASM module"] = t1 - t0;
        setTrinity(trinity);

        // Load circuit
        const t2 = performance.now();
        const circuitResponse = await fetch("/simple_16bit_add.txt");
        if (!circuitResponse.ok) {
          throw new Error(
            `Failed to load circuit: ${circuitResponse.statusText}`
          );
        }
        const circuitText = await circuitResponse.text();
        const t3 = performance.now();
        timings.current["Load circuit file"] = t3 - t2;

        // Parse circuit (assuming parse_circuit is available)
        const t4 = performance.now();
        const parsedCircuit = trinity.parseCircuit(circuitText, 16, 16, 16);
        const t5 = performance.now();
        timings.current["Parse circuit"] = t5 - t4;
        setCircuit(parsedCircuit);

        // Set up initial setup object
        const t6 = performance.now();
        //const setupObj = trinity.TrinityWasmSetup("Halo2");
        const paramsResponse = await fetch("./halo2params.bin");
        if (!paramsResponse.ok) {
          throw new Error(
            `Failed to fetch halo2params.bin: ${paramsResponse.statusText}`
          );
        }
        const paramsBytes = new Uint8Array(await paramsResponse.arrayBuffer());
        const setupObj = TrinityWasmSetup.from_full_params_bytes(paramsBytes);

        console.log("Inspecting loaded setup object:", setupObj.inspect());

        const t7 = performance.now();
        timings.current["Create Trinity setup"] = t7 - t6;
        setSetup(setupObj);

        setComputationState("setup_done");
      } catch (err) {
        setError((err as Error).toString());
        setComputationState("error");
      } finally {
        setLoading(false);
      }
    }

    setup();
  }, []);

  // Step 1: Evaluator commits to input
  const handleEvaluatorCommit = () => {
    if (!trinity || !setup) return;

    try {
      const t0 = performance.now();
      const evaluatorObj = trinity.TrinityEvaluator(
        setup,
        intToUint8Array2(evaluatorInput)
      );
      const t1 = performance.now();
      timings.current["Create evaluator"] = t1 - t0;

      setEvaluator(evaluatorObj);
      setComputationState("evaluator_committed");
    } catch (err) {
      setError((err as Error).toString());
      setComputationState("error");
    }
  };

  // Step 2: Garbler creates garbled circuit
  const handleGarble = () => {
    if (!trinity || !setup || !evaluator || !circuit) return;

    try {
      const t0 = performance.now();
      const garblerObj = trinity.TrinityGarbler(
        evaluator.commitment_serialized,
        setup,
        intToUint8Array2(garblerInput),
        circuit
      );
      const t1 = performance.now();
      timings.current["Create garbler"] = t1 - t0;

      setGarbler(garblerObj);
      setComputationState("circuit_garbled");
    } catch (err) {
      setError((err as Error).toString());
      setComputationState("error");
    }
  };

  // Step 3: Evaluator evaluates the circuit
  const handleEvaluate = () => {
    if (!evaluator || !garbler || !circuit) return;

    try {
      const t0 = performance.now();
      const computationResult = evaluator.evaluate(garbler, circuit);
      const t1 = performance.now();
      timings.current["Evaluate circuit"] = t1 - t0;

      console.log("BENCHMARK SUMMARY:");
      const logOrder = [
        "Import WASM module",
        "Load circuit file",
        "Parse circuit",
        "Create Trinity setup",
        "Create evaluator",
        "Create garbler",
        "Evaluate circuit",
      ];

      let totalExecutionTime = 0;
      logOrder.forEach((key) => {
        if (timings.current[key] !== undefined) {
          console.log(`${key}: ${timings.current[key].toFixed(2)}ms`);
          totalExecutionTime += timings.current[key];
        }
      });
      console.log(`Total execution time: ${totalExecutionTime.toFixed(2)}ms`);

      console.log("Computation result:", computationResult);
      const resultAsInteger = booleanArrayToInteger(computationResult);
      setResult(resultAsInteger);
      setComputationState("result_computed");
    } catch (err) {
      setError((err as Error).toString());
      setComputationState("error");
    }
  };

  // Reset the computation
  const handleReset = () => {
    setEvaluator(null);
    setGarbler(null);
    setResult(null);
    setError(null);
    timings.current = {
      ...timings.current,
      "Create evaluator": 0,
      "Create garbler": 0,
      "Evaluate circuit": 0,
    };
    setComputationState("setup_done");
  };

  return (
    <div className="app">
      <header className="header">
        <h1>Trinity 2PC Demo</h1>
        <p>
          <p>
            Secure two-party computation using Laconic OT and garbled circuits.
          </p>
          <p>The circuit is performing a simple add over private inputs.</p>
        </p>
      </header>

      <main className="main">
        <div className="party evaluator">
          <h2>Evaluator</h2>
          <div className="input-container">
            <label htmlFor="evaluatorInput">Input:</label>
            <input
              id="evaluatorInput"
              type="number"
              min="0"
              max="65535"
              value={evaluatorInput}
              onChange={(e) => {
                const val = parseInt(e.target.value);
                setEvaluatorInput(
                  isNaN(val) ? 0 : Math.max(0, Math.min(65535, val))
                );
              }}
              disabled={computationState !== "setup_done"}
            />

            {/* Evaluator Actions */}
            <div className="actions">
              {computationState === "setup_done" && (
                <button
                  onClick={handleEvaluatorCommit}
                  className="action-button"
                  disabled={loading}
                >
                  Create Commitment
                </button>
              )}

              {computationState === "circuit_garbled" && (
                <button
                  onClick={handleEvaluate}
                  className="action-button"
                  disabled={loading}
                >
                  Evaluate Circuit
                </button>
              )}
            </div>
          </div>

          <div className="steps">
            <div
              className={`step ${computationState !== "initial" ? "done" : ""}`}
            >
              Initialize Setup
            </div>
            <div
              className={`step ${
                computationState !== "initial" &&
                computationState !== "setup_done"
                  ? "done"
                  : ""
              }`}
            >
              Create Commitment
            </div>
            <div
              className={`step ${
                computationState === "result_computed" ? "done" : ""
              }`}
            >
              Evaluate Circuit
            </div>
          </div>
        </div>

        <div className="protocol">
          <div className="computation-state">
            Current state:{" "}
            <span className="state-value">
              {computationState.replace(/_/g, " ")}
            </span>
          </div>

          <div className="data-flow">
            {computationState !== "initial" &&
              computationState !== "setup_done" && (
                <div className="message sent">Commitment sent to Garbler →</div>
              )}

            {computationState !== "initial" &&
              computationState !== "setup_done" &&
              computationState !== "evaluator_committed" && (
                <div className="message received">
                  ← Garbled circuit received
                </div>
              )}
          </div>

          {error && <div className="error">Error: {error}</div>}

          {result !== null && (
            <div className="result">
              <h3>Result: {result}</h3>

              <button onClick={handleReset} className="reset-button">
                Reset Computation
              </button>
            </div>
          )}
        </div>

        <div className="party garbler">
          <h2>Garbler</h2>
          <div className="input-container">
            <label htmlFor="garblerInput">Input:</label>
            <input
              id="garblerInput"
              type="number"
              min="0"
              max="65535"
              value={garblerInput}
              onChange={(e) => {
                const val = parseInt(e.target.value);
                setGarblerInput(
                  isNaN(val) ? 0 : Math.max(0, Math.min(65535, val))
                );
              }}
              disabled={computationState !== "evaluator_committed"}
            />

            {/* Garbler Actions */}
            <div className="actions">
              {computationState === "evaluator_committed" && (
                <button
                  onClick={handleGarble}
                  className="action-button"
                  disabled={loading}
                >
                  Create Garbled Circuit
                </button>
              )}
            </div>
          </div>

          <div className="steps">
            <div
              className={`step ${computationState !== "initial" ? "done" : ""}`}
            >
              Initialize Setup
            </div>
            <div
              className={`step ${
                computationState !== "initial" &&
                computationState !== "setup_done" &&
                computationState !== "evaluator_committed"
                  ? "done"
                  : ""
              }`}
            >
              Create Garbled Circuit
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
