{ pkgs, lib, stdenv, dpdk_19_11, libbsd, pkg-config }:

stdenv.mkDerivation {
  name = "libndpip";

  src = ./.;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ dpdk_19_11 libbsd ];

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
