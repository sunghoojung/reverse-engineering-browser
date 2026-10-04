# Native console bridge

`reb-console` is the dependency-free C++20 transport for Origin Trace's Console
panel. The Rust backend launches its binary pipe mode and owns the disposable
custom Brave process. The app bundles it as `OriginTraceNativeConsole`.

```sh
make native-console-build
make native-console-check
```

The check uses a synthetic browser wire peer. Actual Blink/V8 checks require a
rebuilt custom browser and the command in
[Native Console v2](../../protocol/native-console-v2.md).

For optional terminal development, set `REB_BRAVE_BINARY` to that executable
and run `make native-console`. Select a document using `:targets` and `:use ID`;
`:begin` and `:end` enclose multiline JavaScript. `REB_CONSOLE_REPL=0` enables
scripted stdin without prompts. Output is bounded TOON, errors exit nonzero,
and version/help do not launch a browser. This launcher owns a fresh private
profile and stops its browser process group when the console ends.
