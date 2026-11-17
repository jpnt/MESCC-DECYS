"""Extract the verbatim SAE hunt loop from upstream wpa.c (run once)."""
import pathlib
root = pathlib.Path(__file__).resolve().parent
src = (root / "upstream" / "sae_2.3.c").read_text()
i = src.index('static int sae_derive_pwe_ecc')
j = src.index('static int sae_derive_pwe_ffc')
(root / "sae_derive_pwe_pre_dragonblood.inc").write_text(src[i:j])
print("wrote sae extract")
