# Hypha README and repository-card assets



These are original, code-generated illustrations. They contain no device

screenshots, contact records, conversation text, or live network measurements.



| File | Use |

| --- | --- |

| `hypha-network.gif` | Eight-second looping README explanation, 1200 × 480. |

| `hypha-network.svg` | Static vector alternative; selected by the README's reduced-motion source when supported. |

| `repo-card.png` | Ready-to-upload GitHub social preview, 1280 × 640, solid background. |

| `repo-card-template.svg` | Editable, self-contained social-card template with the approved logo embedded unchanged. |



## Edit or rebuild



The source layout and wording live in:



- `tools/branding/build_readme_art.py`: SVG plus GIF; requires Python and Pillow.

- `tools/branding/build_repo_card.mjs`: editable SVG plus PNG; requires Node.js

  and `sharp` for the PNG export. `--svg-only` needs only Node.js.



Run from the repository root:



```sh

python tools/branding/build_readme_art.py

node tools/branding/build_repo_card.mjs --svg-only

```



For a PNG rebuild, make `sharp` available to the script. One isolated option:



```powershell

npm install --prefix artifacts/readme-art-deps --no-save sharp

$env:HYPHA_GRAPHICS_NODE_MODULES = Join-Path (Get-Location) 'artifacts/readme-art-deps/node_modules'

node tools/branding/build_repo_card.mjs

```



The renderer uses installed Segoe UI or its font fallback. The font files are not

bundled. The checked-in PNG is ready to use without installing a renderer.



You can also edit the SVG directly in a vector editor. Text stays editable, all

logo data is embedded, and important content has an 80 px safe inset. To inspect

the crop guides, change the `safe-area-guides` group's `display="none"` to

`display="inline"`; hide it again before export. Keep the final image at 1280 × 640.



## Set the GitHub social preview



Once a reviewed public release is ready, upload `repo-card.png` through the

repository's **Settings → General → Social preview → Edit**. It has not been

uploaded or configured by this change. The local engineering repository remains

private and still needs the [publication cleanup](../../docs/OPEN_SOURCE_READINESS_2026-10-27.md).



GitHub recommends 1280 × 640 pixels and an image under 1 MB; see its

[official social-preview guide](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/customizing-your-repositorys-social-media-preview).



Original generated artwork is PolyForm Noncommercial 1.0.0; see [LICENSE](../../LICENSE).

The approved mark comes from `assets/images/hypha-app-icon.png`. The root README's

technology badges use Shields.io's corresponding Flutter, Kotlin, Rust, and

Espressif logos; these identify the stack and do not imply endorsement.

