# Releasing fauxbus

The ritual, written down.  The point of a checklist is that a release
cut under time pressure walks the same path as one cut with all the
time in the world.

## 0. The tether posture, stated honestly

SPEC's conformance tether has two legs: Fauxbus on every CI run (live
since SPEC v0.2.5 — the *spec's* version counter, not a package tag,
and this file names both kinds within a few lines of each other), and
the real Globus service, env-gated, before each release.  The second
leg needs a sacrificial tenancy, and **none exists anywhere yet** —
dev deliberately has no Globus tenancy (that absence is why fauxbus is
load-bearing for its first consumer).

So, until the first recording session is possible:

- Every release ships with the **PROVISIONAL inventory** in its release
  notes.  Generate it: `grep -rn PROVISIONAL src/`.  The batch
  membership response document is the standing #1.
- The moment a sacrificial tenancy exists, the recording session
  becomes **release-blocking for every release after it becomes
  possible**.  A gate nobody can run is worse than an honest gap —
  but a gate somebody could run and didn't is just a gap.

## 1. Green, current, coordinated

- [ ] CI green on `main` — lint, conformance-enforced suite, and wheel
      across 3.11/3.12/3.13, plus the image build-and-boot step.
- [ ] SPEC.md changelog carries an entry for this version.
- [ ] **The re-pin handshake.**  Downstream consumers may pin fauxbus
      in more than one place (the first consumer pins it twice: once
      as an application dependency, once in its deploy stack).  Hand
      consumers the new tag so every pin moves **in one commit** —
      never let pins drift, because a half-repinned consumer tests two
      different fakes and believes it tested one.

## 2. Version and tag

- [ ] `src/fauxbus/__init__.py`: drop the `.dev0` from `__version__`
      (e.g. `0.1.0.dev0` → `0.1.0`).  **That one line is the whole
      bump** — pyproject reads it at build time.  It did not use to be:
      the version lived in two files, this checklist named only one of
      them, and v0.1.0 and v0.1.1 both shipped reporting `0.1.0.dev0`
      to `--version`, the banner, and `GET /_fauxbus/`.  A checklist
      that names one of two sources of truth is a checklist that walks
      you confidently past the bug.
- [ ] Confirm the artifact agrees before you tag: `python -m build`
      then check `dist/` is named for the version you meant.  (CI's
      tagged pipeline enforces this too, but after the tag exists.)
- [ ] Commit `Release vX.Y.Z`, push the commit, and **wait for CI to go
      green before the tag exists.**  Tag only what CI has proved.
- [ ] Tag `vX.Y.Z` and push the tag.

      > ⚠️ **Since 2026-08-08, pushing a tag publishes to PyPI.**
      > The `publish-pypi` step is armed and fires on `event: tag`.
      > A PyPI upload is burn-once — that version number can never be
      > re-uploaded, not even after you delete the release.  So the tag
      > push is the point of no return, not the announcement.  Anything
      > you want to check about the artifact, check *before* this line.
      > A tag pointing at a `.dev0` commit dies in the step's version
      > guard rather than on PyPI, which is the one mistake the
      > automation catches for you.  It does not catch a wrong artifact
      > that is honestly named.

- [ ] Immediately follow with a bump to the next `.dev0` so `main` is
      never ambiguous about whether it is a release.

## 3. Artifacts

- The wheel: CI builds it on every push; the tagged pipeline's wheel is
  the release artifact.
- The image: built from the tag via the shipped `Containerfile`.  It
  carries its own CycloneDX SBOM at `/usr/share/fauxbus/sbom.json`,
  generated at image build from a clean install of the wheel and
  asserted by CI — for a zero-dependency package, the SBOM is the
  receipt for the packaging claim.  A bare wheel install can mint the
  same receipt: `cyclonedx-py environment <venv-python>`.
- Publication: **PyPI — live and automatic since 2026-08-08.**
  <https://pypi.org/project/fauxbus/>.  You do not run `twine`.  Push
  the tag and the `publish-pypi` step builds, checks and uploads.  All
  you owe it is a tag whose version matches the artifact, which its own
  guard enforces.

  Read the step before you trust it — it is annotated with why it has
  no `--skip-existing` (that flag would turn a force-moved tag into a
  silent no-upload that goes green) and why an empty token is caught by
  name rather than left to twine's misleading auth error.

  <details><summary>How it was armed, kept for the next new package</summary>

  1. **First upload is manual**, from a clean tag build:
     `git archive vX.Y.Z | tar -x -C /tmp/rel`, then `python -m build`
     and `twine upload dist/*` from there.  Manual because the first
     upload is what creates the PyPI project a token can be scoped to —
     you cannot scope a credential to something that does not exist.
     Done for 0.1.2 on 2026-08-07 with an account-scoped token, which
     was deleted immediately afterward.
  2. **Scope a token** to the project; store it as the Woodpecker repo
     secret `pypi_token`, **allowed for the `tag` event**.  Woodpecker
     injects a secret only into events it is explicitly allowed for,
     and a secret that is not allowed arrives as an empty string rather
     than an error.
  3. **Restore the parked `publish-pypi` step** in `.woodpecker.yml`.
  4. **Then, and only then, flip the docs**: README's install line
     becomes the real `pipx install fauxbus`, and the blog draft's
     "not on PyPI yet" caveat goes.  Docs never promise a package
     that isn't live.

  </details>

  Prerequisite for all of it was public homepage/issues URLs in
  pyproject (the mirror decision), satisfied 2026-08-07 — they point at
  `github.com/atmarx/fauxbus`, which is public and has issues enabled.
  A container registry remains a decision not yet taken.

## 4. Tell the people

- Announce the release where consumers actually look, with the
  PROVISIONAL inventory and the re-pin pointer.  Consumers learn about
  releases from the announcement, not from watching the repo.
