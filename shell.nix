{ pkgs ? import <nixpkgs> {
  overlays = (import /etc/nixos/dpdk-overlay.nix);
} }:

pkgs.mkShell {
  name = "eqds-tcp-perf";

  buildInputs = with pkgs; [
    dpdk_19_11
    gcc
    glibc.static
    libbsd
    pkg-config
  ];
}
