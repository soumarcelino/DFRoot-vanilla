# DFRoot vanilla

Runner ADB sem APK para o Samsung SM-S918B com kernel Android 13/5.15.

## Projetos

Cada binário gerado possui seu próprio diretório e script de build:

| Diretório | Saída | Função |
| --- | --- | --- |
| `dirtyfrag/` | `dirtyfrag.ko` | Módulo GKI Android 13/5.15 |
| `splicehelper/` | `splicehelper` | Helper ARM64 estático |
| `libexp/` | `libexp.so` | Exploit JNI; incorpora o módulo e o helper |
| `runner/` | `runner.jar` | Entrada Java executada por `app_process` |
| `ksud/` | `ksud` | Único binário pré-compilado mantido no repositório |

`build.sh` orquestra os quatro projetos e grava os resultados temporários em
`out/`, que não é versionado.

## Executar

Após um boot limpo:

```sh
./run.sh RXCX602E20X
```

O script compila tudo, envia `runner.jar`, `libexp.so` e `ksud` para
`/data/local/tmp`, executa o JAR e confirma o root com `su -c id`.

Não execute duas vezes no mesmo boot. O script bloqueia essa tentativa.
