# Drift-Corrected Noise Model Analysis

This directory contains a Marimo notebook for analyzing drift-corrected noise model results from the op_noise analysis tool.

## Running the Noise Analysis Tool

### Basic Testing Parameters

For initial testing and development:

```bash
cargo run --features="benchmark_system_info" --release --example op_noise -- \
    analyze-cmux-tree params \
    --parameter-set-name default_128 \
    --std-sample-count 100 \
    --std-depth 1024 \
    --drift-sample-count 100 \
    --drift-depth 256
```

### High Confidence Parameters

For production analysis requiring high statistical confidence:

```bash
cargo run --features="benchmark_system_info" --release --example op_noise -- \
    analyze-cmux-tree params \
    --parameter-set-name default_128 \
    --std-sample-count 10000 \
    --std-depth 4096 \
    --drift-sample-count 10000 \
    --drift-depth 512
```

The high confidence analysis may take several hours to complete but provides reliable statistical characterization of the noise model.

## Running the Analysis Notebook

After generating analysis data, run the notebook to view results:

```bash
cd parasol_runtime/examples/op_noise/notebooks
nix-shell --run "marimo run cmux-noise-with-drift.py"
```

The noise analysis tool outputs results to `noise_analysis/analyze_cmux_tree.json`. The notebook automatically searches common locations for this file.
