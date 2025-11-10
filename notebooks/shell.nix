let
  pkgs = import (fetchTarball {
    # Pinned to nixpkgs-master
    url =
      "https://github.com/NixOS/nixpkgs/archive/b24caa9c507c7b33fb7573f20d71cab3ac3c1b41.tar.gz";
    sha256 = "1n8pcbr63ixf7y1zywki9giys1sjqrhlyib080p44bpmqvb5i1bs";
  }) { };

  # Base Python interpreter
  basePython = pkgs.python313;

  # Override Python packages to include marimo 0.17.7
  python = basePython.override {
    self = python;
    packageOverrides = pself: psuper:
      let
        customPackages = import ./marimo-override.nix {
          inherit pkgs;
          python = basePython;
        };
      in {
        msgspec-m = customPackages.msgspec-m;
        marimo = customPackages.marimo;
      };
  };

  pythonEnv = python.withPackages (ps:
    with ps; [
      cytoolz
      ipython
      jupyter
      jupyterlab
      marimo
      matplotlib
      mcp
      numpy
      scipy
      virtualenv
    ]);

in pkgs.mkShell { buildInputs = [ pythonEnv pkgs.ty pkgs.ruff pkgs.nodejs ]; }
