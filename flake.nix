{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
  };
  outputs =
    inputs:
    let
      eachSystem = inputs.nixpkgs.lib.genAttrs (import inputs.systems);
      pkgsFor = eachSystem (
        system:
        import inputs.nixpkgs {
          inherit system;
        }
      );
    in
    {
      devShells = eachSystem (system: {
        default = pkgsFor.${system}.mkShell {
          packages = with pkgsFor.${system}; [
            go
          ];

          shellHook = ''
            go mod tidy
          '';
        };
      });
    };
}
