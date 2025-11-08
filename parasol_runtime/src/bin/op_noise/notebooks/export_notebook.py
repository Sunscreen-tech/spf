#!/usr/bin/env python3
"""
Simple script to export marimo notebook to ipynb format with all outputs.
Runs the notebook headlessly and saves to published directory.
"""

import os
import subprocess
import sys

def main():
    # Set working directory to notebook directory
    notebook_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(notebook_dir)
    
    # Create published directory
    published_dir = os.path.join(notebook_dir, 'published')
    os.makedirs(published_dir, exist_ok=True)
    
    notebook_name = 'cmux-noise-with-drift.py'
    output_name = 'cmux-noise-with-drift.ipynb'
    output_path = os.path.join(published_dir, output_name)
    
    print(f'Exporting {notebook_name} to {output_path}')
    
    try:
        # Export to ipynb with outputs (marimo will run the notebook automatically)
        print('Exporting to ipynb format with outputs...')
        export_cmd = ['nix-shell', '--run', f'marimo export ipynb {notebook_name} -o {output_path} --include-outputs']
        result = subprocess.run(export_cmd, capture_output=True, text=True, cwd=notebook_dir)
        
        if result.returncode != 0:
            print(f'Export failed with return code {result.returncode}')
            print('STDOUT:', result.stdout)
            print('STDERR:', result.stderr)
            return 1
        
        print(f'Successfully exported notebook to {output_path}')
        
        # Check if file was created
        if os.path.exists(output_path):
            file_size = os.path.getsize(output_path)
            print(f'Output file size: {file_size} bytes')
        else:
            print('Warning: Output file was not created')
            return 1
            
    except Exception as e:
        print(f'Error during export: {e}')
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())