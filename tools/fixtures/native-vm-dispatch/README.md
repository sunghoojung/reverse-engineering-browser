# Owned native dispatch references

These JavaScript-shaped sources are inert reference descriptions for the fixed
native register and stack programs in `protocol/owned-vm-programs-v1.json`.
`references.json` binds their exact bytes and the entire manifest digest. Their
PCs are instruction indices; arrays are declarations, not captured guest bytes.

No check, analyzer or recorder executes these sources. The native C++ fixture
emits real cooperative samples. The synthetic analyzer acceptance test explicitly
binds those samples to these reference artifacts to test storage, identity,
static handler matching and presentation. That binding is a supplied declaration,
not proof that the native interpreter executed JavaScript. No existing JS fixture
opcode is remapped, and unknown native-to-source matches stay unknown.
