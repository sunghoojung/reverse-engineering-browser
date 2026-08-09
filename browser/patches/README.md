# Browser Patch Experiments

Use this directory for small, reviewable patch experiments before their permanent location in the private `brave-core` repository is known.

Each patch must document:

- the upstream Brave or Chromium revision;
- the target source file and subsystem;
- the observable behavior it adds;
- the hot-path cost and failure behavior;
- the test that proves normal page behavior remains unchanged.

Do not store generated Chromium source or build output here.
