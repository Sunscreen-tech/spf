{ pkgs, python }:

let
  # Override msgspec to use marimo-team's fork with Python 3.14 wheel support
  msgspec-m = python.pkgs.msgspec.overridePythonAttrs (old: {
    version = "0.19.2";
    src = pkgs.fetchFromGitHub {
      owner = "marimo-team";
      repo = "msgspec";
      rev = "0.19.2";
      hash = "sha256-rZv/6xZsE6NNbQnTXq5HKsAHm3yHpzlrgNOP2v8s0KI=";
    };
    build-system = with python.pkgs; [ setuptools versioneer ];
  });

  # Override marimo to version 0.17.7
  marimo = python.pkgs.marimo.overridePythonAttrs (old: {
    version = "0.17.7";
    src = python.pkgs.fetchPypi {
      pname = "marimo";
      version = "0.17.7";
      hash = "sha256-010q5LEiHoF0urPzvX7GeR8JV+/u3GLoJO/85odkQzM=";
    };

    # Replace msgspec dependency with msgspec-m
    dependencies = builtins.map (dep:
      if dep.pname or "" == "msgspec" then msgspec-m else dep
    ) (old.dependencies or [ ]) ++ pkgs.lib.optionals (!(builtins.any (dep: (dep.pname or "") == "msgspec") (old.dependencies or [ ]))) [ msgspec-m ];
  });

in {
  inherit msgspec-m marimo;
}
