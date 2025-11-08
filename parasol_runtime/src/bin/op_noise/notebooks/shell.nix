let
  pkgs = import (fetchTarball {
    # Pinned to nixpkgs-master
    url =
      "https://github.com/NixOS/nixpkgs/archive/b24caa9c507c7b33fb7573f20d71cab3ac3c1b41.tar.gz";
    sha256 = "1n8pcbr63ixf7y1zywki9giys1sjqrhlyib080p44bpmqvb5i1bs";
  }) { };

  python = pkgs.python313;

  pythonEnv = python.withPackages (ps:
    with ps; [
      cytoolz
      ipython
      jupyter
      jupyterlab
      marimo
      matplotlib
      numpy
      scipy
      virtualenv
    ]);

in pkgs.mkShell { buildInputs = [ pythonEnv pkgs.ty pkgs.ruff pkgs.nodejs ]; }
