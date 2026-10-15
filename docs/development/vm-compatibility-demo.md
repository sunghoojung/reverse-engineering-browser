# VM compatibility example and semantic colors

The VM workspace uses violet for primary actions, teal for selected controls and
instructions, amber for changed values and Pause/Reset, and rose for Stop/Close
and clearing traces. Text labels, selection rails, pressed/selected attributes,
and explicit change text remain available without color perception. Dark and
light palettes have numerical text contrast checks (at least 4.5:1) and focus
checks (at least 3:1); rendered checks verify computed colors and keyboard focus.
The existing layout and responsive row-count requirements are unchanged.

## Generate and inspect the owned example

    node tools/generate-vm-compatibility-demo.mjs /tmp/owned-vm-demo.json
    node tools/check-vm-compatibility-demo.mjs

Open VM tab → Execution workspace → Import trace and select
that JSON file. Existing output files are refused. The generated trace is small,
uses the normal bounded import contract, and contains no host data. Importing
it does not start a native fixture or execute supplied code in the application.

This is an independently authored fixed-program compatibility fixture inspired
by the open-source [16bitjs](https://github.com/francisrstokes/16bitjs) ISA at
commit [7182b81613e8278aafe4ef1da13dd3988eae2f77](https://github.com/francisrstokes/16bitjs/tree/7182b81613e8278aafe4ef1da13dd3988eae2f77).
The reference project is MIT-licensed; see its
[license](https://github.com/francisrstokes/16bitjs/blob/7182b81613e8278aafe4ef1da13dd3988eae2f77/LICENSE).
No upstream runtime, terminal-I/O modules, npm packages or downloaded code are
loaded. The example is not a claim of full ISA conformance, upstream execution,
unknown-VM decompilation, browser capture or recovered opcode semantics.

The CLI actually executes only the 15 words fixed in the owned recorder.
It accepts no program input. Fourteen independently specified expected
transitions test arithmetic, call/return, a taken branch, memory, stack and halt.
The supplied hex column contains the full instruction word serialized as two
little-endian bytes, not just the low-nibble opcode. Declared assembly aliases
below are documentation. On import, the UI automatically tests its bounded
candidate-operation set against retained transitions and labels matching
candidates as inferred; unmatched operations remain unknown. Inference does
not prove the declared ISA semantics. An optional hypothesis file separately
validates a supplied mapping, and matching cases do not prove general validity.

| Word address | Raw word | Declared alias | Purpose |
|---|---|---|---|
| 0 | 0601 | MVI A,6 | First factor |
| 1 | 0711 | MVI B,7 | Second factor |
| 2 | 0d31 | MVI D,13 | Function address |
| 3 | 0035 | CAL D | Push return address4 |
| 4 | 1003 | STA A,64 | Store product |
| 5 | 102b | LDA C,64 | Read product |
| 6 | 2a11 | MVI B,42 | Expected result |
| 7 | 0a31 | MVI D,10 | Success branch |
| 8 | 0366 | JEQ C,B,D | Skip failure instruction |
| 9 | ff21 | MVI C,255 | Unexecuted failure path |
| 10 | 0087 | PSH C | Push result |
| 11 | 0018 | POP B | Restore result |
| 12 | 003d | HLT | Halt after fetch |
| 13 | 0244 | MUL A,B | Calculate42 |
| 14 | 001d | RET | Pop return address |

Registers0–4 mean A,B,C,D,SP. PC and memory addresses use word units. SP is the
logical stack length; the stack shows live entries only. Memory retains all
15 code words and data address64, initially known zero. Other memory is omitted
and therefore unknown in this projection. The artifact SHA256 hashes exactly
these15 words serialized little-endian, not the interpreter implementation.

Useful inspection points:
- Sequence3: call changes PC3→13 and pushes return address4.
- Sequence4: multiply changes register0 from6→42.
- Sequence6: memory64 changes from known zero→42.
- Sequence10: branch changes PC8→10; the failure instruction is not observed.
- Sequence11/12: stack grows to[42], then empties.
- Sequence13: HLT sets halted=true with PC13. That PC is the post-fetch cursor,
  not evidence that the multiply instruction ran again.

The rendered acceptance test records this fixture, imports the resulting JSON
through the real file input, selects the store/halt steps with native keyboard
controls, and captures desktop screenshots. Actual rendering remains a separate
platform gate; mathematical color tests alone do not establish visual quality.
