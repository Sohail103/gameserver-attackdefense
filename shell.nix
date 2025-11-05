{ pkgs ? import <nixpkgs> {} }:
let
  python = pkgs.python312;
  pythonWithPackages = python.withPackages (ps: with ps; [
    flask
    apscheduler
    requests
    # nmapthon2  
  ]);
in
pkgs.mkShell {
  name = "ctf-server-env";
  buildInputs = [
    pythonWithPackages
    pkgs.nmap
    pkgs.git
  ];
  
  shellHook = ''
    echo "nix shell started with flask, apscheduler and requests"
  '';
}
