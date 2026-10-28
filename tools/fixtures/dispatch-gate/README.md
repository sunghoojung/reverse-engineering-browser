# Dispatch claim-gate regressions

These are authored synthetic JavaScript probes supplied by the fourth reviewer.
They contain no third-party captures or function-map data. The backend tests
exercise them through the analysis and workspace path, checking exact retained
handler counts and counted withholding. Unicode window alignments and scalable
adversarial inputs are generated in the Rust tests.

The fixed base snapshot predates these additional regressions. Its input list
and bytes are intentionally unchanged; CLI differential validation also covers
this directory separately.
