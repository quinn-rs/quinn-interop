{ pkgs ? import <nixpkgs> {} }:

with pkgs;
let quinn = builtins.fetchGit {
      name = "quinn";
      url = "git@github.com:quinn-rs/quinn.git";
      rev = "fffc513624dafa14af97e29377be9dcbf31b6885";
      outpath = "quinn";
    };
in
mkShell {
  buildInputs = [
  ];
}
