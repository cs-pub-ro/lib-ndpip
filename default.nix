{ pkgs, lib, stdenv, dpdk, libbsd, pkg-config }:

stdenv.mkDerivation {
  name = "libndpip";

  src = ./.;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ dpdk libbsd ];

  dontStrip = true;

  buildPhase = ''
    make -f Makefile.linux-dpdk
  '';

  installPhase = ''
    mkdir -p $out/lib
    cp libndpip.a $out/lib/
    cp -r include $out
  '';
}
