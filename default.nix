{ pkgs ? import <nixpkgs> { } }:
let manifest = (pkgs.lib.importTOML ./Cargo.toml).package;
in
pkgs.rustPlatform.buildRustPackage rec {
  pname = manifest.name;
  version = manifest.version;
  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "keepass-0.6.1" = "sha256-nQRBH/BS5uh4jkR0w/AIxYkotWyhbIw8BvFs7cSzlqc=";
    };
  };
  src = pkgs.lib.cleanSource ./.;

  buildInputs = [
    pkgs.darwin.apple_sdk.frameworks.CoreServices
    pkgs.darwin.apple_sdk.frameworks.AppKit
   ];
}