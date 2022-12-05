# STRINGS

This is a library to statically de-obufscate strings from malware binaries. It performs extraction of:
- static strings: "regular" ASCII and UTF-16LE strings
- stack strings: strings constructed on the stack at run-time
- tight strings: special form of stack strings, decoded on the stack
- decoded strings: strings decoded in a function

This is a rust port of the original Floss project initially written in python.
[See original](https://github.com/mandiant/flare-floss).

Most of the work is also guided by the [Goblin Project.](https://github.com/m4b/goblin)

## USAGE
```toml
[dependencies]
strings = { git = "https://github.com/marirs/strings-rs", branch = "master" }
```
And

```rust
use log::Level;
use simple_logger::init_with_level;
use floss::analyze;
use floss::results::{StaticString, StringOptions};

pub fn main(){
    init_with_level(Level::Trace);
    let signature_path = "(embedded signatures)";
    let results = analyze("data/test-decode-to-stack.exe", vec![StringOptions::StaticString(StaticString::default())], vec![], "sc32",signature_path, false);
    println!("{:?}", results);
}
```
---
LICENSE: Apache 2.0