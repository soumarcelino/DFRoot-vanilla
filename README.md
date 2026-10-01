# DFRoot ADB runner

Runner mínimo e sem APK para o `SM-S918B` com kernel Android 13/5.15.

```sh
./run.sh RXCX602E20X
```

O comando compila, envia os três artefatos para `/data/local/tmp`, executa o
JAR com `app_process` e confirma o resultado com `su -c id`.

Não execute duas vezes no mesmo boot. O script bloqueia essa tentativa; para
uma nova execução, reinicie o aparelho primeiro.

## Estrutura

- `src/java/`: entrada do `app_process` e configuração IPsec.
- `src/native/`: JNI, DirtyFrag, ELF, shellcode e helper.
- `module/dirtyfrag.c`: código-fonte do módulo específico do device.
- `payload/ksud`: KernelSU daemon.
- `build.sh`: compila o módulo com o GKI DDK e gera os artefatos em `build/`.
- `run.sh`: build, push, execução e verificação via ADB.
