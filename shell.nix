{ pkgs ? import <nixpkgs> {} }:
let
  python = pkgs.python312;
  pythonWithPackages = python.withPackages (ps: with ps; [
    flask
    apscheduler
  ]);
in
pkgs.mkShell {
  name = "ctf-server-env";
  buildInputs = [
    pythonWithPackages
    pkgs.nmap
    pkgs.git
    pkgs.openssl
  ];
  
  shellHook = ''
    echo "nix shell started with flask, apscheduler"
  '';
}
