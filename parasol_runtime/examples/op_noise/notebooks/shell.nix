let
  pkgs = import (fetchTarball {
    # Pinned nixpkgs nixpkgs-25.05-darwin
    url =
      "https://github.com/NixOS/nixpkgs/archive/3535321020f5617f3ca73065118984b1325331ab.tar.gz";
    sha256 = "0z2wrgzpq6868fj4n040p1mqrb32wian1fvs7j4sf8df0mn6qcyf";
  }) { };

  pkgs-unstable = import (fetchTarball {
    # Pinned nixpkgs nixpkgs-25.05-darwin
    url =
      "https://github.com/NixOS/nixpkgs/archive/cab778239e705082fe97bb4990e0d24c50924c04.tar.gz";
    sha256 = "119yw3dqvq6c9kvvk8x1829a3symy6g0cbzjpskx9xhbak4r82cn";
  }) { };

  python = pkgs.python313;

  loroPackage = python.pkgs.buildPythonPackage rec {
    pname = "loro";
    version = "1.5.0";
    pyproject = true;

    src = python.pkgs.fetchPypi {
      inherit pname version;
      hash = "sha256-jyN4YI0ySV4IYVfzexrjvHR77dHknp9BrelQ3c7YZB8=";
    };

    cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
      inherit src;
      name = "${pname}-${version}";
      hash = "sha256-eaUxqg+sH/doa7hIULM7WWZ4YYPlzjuzAlTmamIUQKc=";
    };

    build-system =
      [ pkgs.rustPlatform.maturinBuildHook pkgs.rustPlatform.cargoSetupHook ];

    meta = {
      description = "Data collaborative and version-controlled JSON with CRDTs";
      homepage = "https://github.com/loro-dev/loro-py";
      changelog = "https://github.com/loro-dev/loro-py/releases/tag/${version}";
      license = pkgs.lib.licenses.mit;
    };
  };

  marimoOverride = python.pkgs.marimo.overridePythonAttrs (oldAttrs: rec {
    version = "0.14.16";
    src = python.pkgs.fetchPypi {
      pname = "marimo";
      version = version;
      sha256 = "sha256-8PKRrH+m+HyAcvQBnG6fY1rX77N+AhTyJUPI3ZgwQtE=";
    };

    # Use hatchling build system like original
    build-system = [ python.pkgs.hatchling ];

    # Add loro to dependencies
    dependencies = (oldAttrs.dependencies or [ ]) ++ [ loroPackage ];

    # Keep original python relaxed deps
    pythonRelaxDeps = [ "pycrdt" "websockets" ];

    # Patch pyproject.toml to use hatchling instead of uv_build
    postPatch = ''
            # Replace the entire [build-system] section with hatchling
            sed -i '/^\[build-system\]/,/^\[.*\]/{ /^\[build-system\]/!{ /^\[.*\]/!d; }; }' pyproject.toml
            sed -i '/^\[build-system\]/a\
      requires = ["hatchling"]\
      build-backend = "hatchling.build"' pyproject.toml
    '';

    # Disable checks to avoid dependency issues
    doCheck = false;
    pythonImportsCheck = [ "marimo" ];
  });

  pythonEnv = python.withPackages (ps:
    with ps;
    [ virtualenv jupyter ipython numpy matplotlib jupyterlab scipy cytoolz ]
    ++ [ marimoOverride ]);

in pkgs.mkShell { buildInputs = [ pythonEnv pkgs-unstable.ty pkgs.ruff pkgs.nodejs ]; }
