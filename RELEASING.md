# Releasing fauxbus

The ritual, written down.  The point of a checklist is that a release
cut under time pressure walks the same path as one cut with all the
time in the world.

## 0. The tether posture, stated honestly

SPEC's conformance tether has two legs: Fauxbus on every CI run (live
since v0.2.5), and the real Globus service, env-gated, before each
release.  The second leg needs a sacrificial tenancy, and **none
exists anywhere yet** — dev deliberately has no Globus tenancy (that
absence is why fauxbus is load-bearing for its first consumer).

So, until the first recording session is possible:

- Every release ships with the **PROVISIONAL inventory** in its release
  notes.  Generate it: `grep -rn PROVISIONAL src/`.  The batch
  membership response document is the standing #1.
- The moment a tenancy exists (first target: work's staging tenancy,
  when creds flip), the recording session becomes **release-blocking
  for every release after it becomes possible**.  A gate nobody can
  run is worse than an honest gap — but a gate somebody could run and
  didn't is just a gap.

## 1. Green, current, coordinated

- [ ] CI green on `main` — lint, conformance-enforced suite, and wheel
      across 3.11/3.12/3.13, plus the image build-and-boot step.
- [ ] SPEC.md changelog carries an entry for this version.
- [ ] **The re-pin handshake** (the first consumer's own protocol,
      >>01KZ82F5ECFR8E75GN8162PRMJ): root-cellar pins fauxbus in two
      places — the plane's pyproject and `deploy/rc/modules/fauxbus` —
      and re-pins **both in one commit**.  Post the tag to
      #root-cellar when it exists so they can.  Never let the two pins
      drift; a half-repinned consumer tests two different fakes and
      believes it tested one.

## 2. Version and tag

- [ ] `pyproject.toml`: drop the `.dev0` (e.g. `0.1.0.dev0` → `0.1.0`).
- [ ] Commit `Release vX.Y.Z`, tag `vX.Y.Z`, push commit and tag.
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
- Publication: **PyPI — decided 2026-08-05, not yet armed.**  The name
  is free and the v0.1.0 artifacts pass `twine check`.  The sequence,
  in order, none of it improvised at tag time:
  1. **First upload is manual**, from a clean tag build:
     `git archive vX.Y.Z | tar -x -C /tmp/rel`, then `python -m build`
     and `twine upload dist/*` from there.  Manual because the first
     upload is what creates the PyPI project a token can be scoped to.
  2. **Scope a token** to the project; store it as the Woodpecker
     secret `pypi_token`.
  3. **Restore the parked `publish-pypi` step** at the bottom of
     `.woodpecker.yml` (restore conditions annotated there).  Tags
     publish automatically from then on, with a guard that dies if the
     tag's version disagrees with the built artifacts.
  4. **Then, and only then, flip the docs**: README's install line
     becomes the real `pipx install fauxbus`, and the blog draft's
     "not on PyPI yet" caveat goes.  Docs never promise a package
     that isn't live.

  Prerequisite for all of it: public homepage/issues URLs in
  pyproject (the mirror decision).  A container registry remains a
  decision not yet taken.

## 4. Tell the people

- Post the release to #fauxbus with the PROVISIONAL inventory and the
  re-pin pointer.  The first consumer learns about releases from the
  channel, not from watching the repo.
