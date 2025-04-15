import {
  initTrinity,
  intToUint8Array2,
  CircuitWrapper,
  TrinityModule,
  TrinityWasmSetup,
  TrinityEvaluator,
  TrinityGarbler,
} from "@trinity_2pc/core";
import { useState, useEffect } from "react";
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

  // Initialize Trinity and load circuit
  useEffect(() => {
    async function setup() {
      try {
        // Initialize Trinity
        const trinity = await initTrinity();
        setTrinity(trinity);

        // Load circuit
        const circuitResponse = await fetch("/simple_16bit_add.txt");
        if (!circuitResponse.ok) {
          throw new Error(
            `Failed to load circuit: ${circuitResponse.statusText}`
          );
        }
        const circuitText = await circuitResponse.text();

        // Parse circuit (assuming parse_circuit is available)
        const parsedCircuit = trinity.parseCircuit(circuitText, 16, 16, 16);
        setCircuit(parsedCircuit);

        // Set up initial setup object
        const setupObj = trinity.TrinityWasmSetup("Plain");
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
      const evaluatorObj = trinity.TrinityEvaluator(
        setup,
        intToUint8Array2(evaluatorInput)
      );

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
      const garblerObj = trinity.TrinityGarbler(
        evaluator.commitment_serialized,
        setup,
        intToUint8Array2(garblerInput),
        circuit
      );

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
      const computationResult = evaluator.evaluate(garbler, circuit);
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
