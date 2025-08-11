#!/bin/bash
# Runs the CI commands locally.

set -e

WORKFLOW_FILE=".github/workflows/rust.yml"

if [[ ! -f "$WORKFLOW_FILE" ]]; then
    echo "Error: $WORKFLOW_FILE not found"
    exit 1
fi

# Extract cargo commands from CI workflow in order of appearance
extract_ci_commands() {
    # Simple approach: extract cargo commands and handle RUSTDOCFLAGS separately
    local commands=$(grep -E "run:\s*cargo" "$WORKFLOW_FILE" | \
        sed -E 's/.*run:\s*//' | \
        sed -E 's/^[[:space:]]+|[[:space:]]+$//g' | \
        grep -v "version")
    
    # Check if we have the doc command and need RUSTDOCFLAGS
    echo "$commands" | while IFS= read -r cmd; do
        if [[ "$cmd" == *"cargo doc"* ]]; then
            echo "RUSTDOCFLAGS='-D warnings' $cmd"
        else
            echo "$cmd"
        fi
    done
}

# Parse command line arguments
NO_CONFIRM=false
if [[ "$1" == "--no-confirm" ]]; then
    NO_CONFIRM=true
fi

echo "Running local CI validation..."
echo ""

# Read commands into array (portable approach)
CI_COMMANDS=()
while IFS= read -r line; do
    CI_COMMANDS+=("$line")
done < <(extract_ci_commands)

if [[ ${#CI_COMMANDS[@]} -eq 0 ]]; then
    echo "Error: No suitable CI commands found in $WORKFLOW_FILE"
    exit 1
fi

# Show commands that will be run
echo "Commands to run:"
for i in "${!CI_COMMANDS[@]}"; do
    step=$((i + 1))
    total=${#CI_COMMANDS[@]}
    echo "  [$step/$total] ${CI_COMMANDS[$i]}"
done
echo ""

# Ask for confirmation unless --no-confirm is used
if [[ "$NO_CONFIRM" != true ]]; then
    read -p "Continue? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    echo ""
fi

# Execute each command
for i in "${!CI_COMMANDS[@]}"; do
    cmd="${CI_COMMANDS[$i]}"
    step=$((i + 1))
    total=${#CI_COMMANDS[@]}
    
    # Green header for script output
    echo -e "\033[32m[$step/$total] $cmd\033[0m"
    
    if eval "$cmd"; then
        echo -e "\033[32m✓ Passed\033[0m"
    else
        echo -e "\033[31m✗ Failed: $cmd\033[0m"
        exit 1
    fi
    echo ""
done

echo "All CI checks passed!"
