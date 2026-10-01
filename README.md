# DFRoot Vanilla

A source-focused DFRoot research project for running the DirtyFrag chain from
ADB without an APK. It targets the Samsung SM-S918B Android 13/5.15 kernel ABI.

## Projects

Each generated binary has an independent source directory and build script:

| Directory | Output | Purpose |
| --- | --- | --- |
| `dirtyfrag/` | `dirtyfrag.ko` | Android 13/5.15 GKI kernel module |
| `splicehelper/` | `splicehelper` | Static ARM64 helper |
| `libexp/` | `libexp.so` | JNI exploit library embedding the module and helper |
| `runner/` | `runner.jar` | Java entry point executed through `app_process` |
| `ksud/` | `ksud` | KernelSU daemon required by the tested chain |

The root `build.sh` orchestrates all source builds. Generated artifacts are
written to the ignored `out/` directory and are not committed.

## Build and run

After a clean device boot:

```sh
./run.sh RXCX602E20X
```

The script builds the projects, stages the runtime files under
`/data/local/tmp`, starts the JAR through `app_process`, and verifies the result
with `su -c id`. It refuses to run twice during the same boot.

## References

This research is derived from and should be read alongside:

- [polygraphene/DFReroot](https://github.com/polygraphene/DFReroot/tree/main)
- [diabl0w/DFRoot](https://github.com/diabl0w/DFRoot)

Use only on devices you own or are explicitly authorized to test.

## License

Licensed under the [GNU General Public License v2.0](LICENSE), the same free software license used by the Linux kernel.
