{ pkgs, lib, stdenv, dpdk_19_11, pkg-config }:

stdenv.mkDerivation {
  name = "libndpip";
  src = ./.;
  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ dpdk_19_11 ];
  installPhase = ''
    mkdir -p $out/lib
    cp libndpip.a $out/lib/
  '';
}
