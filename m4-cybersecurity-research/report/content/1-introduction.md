## Why NuttX and its Wi-Fi stack, and why now

This project follows the DECYS research style "Security Analysis of Existing Systems" [@brief]: identify real flaws in a deployed system and demonstrate them. Embedded RTOS security research concentrates on FreeRTOS and Zephyr. NuttX gets less attention, which makes it an interesting target for a course project: the interesting question is not "is there a bug in NuttX" (there is always a bug) but "what does the NuttX project *do* about bugs, and does that answer change once NuttX is what a hundred million consumer devices boot?".

The second half of that question is why the timing matters. NuttX shipped in the Pebble watch and in a long tail of industrial panels, but its big consumer moment is Xiaomi's openvela (formerly Vela OS), the OS Xiaomi publishes for wearables, bands, speakers and appliances. Xiaomi's own documentation states the kernel "is built upon Apache NuttX" and describes POSIX conformance as the reason developers can port Linux software across with little effort. A generic memory-safety bug that only cost hobbyists a reboot now costs a vendor an OTA across a large fleet.

WPA2 matters here for the simplest reason: it is the only thing standing between a drive-by attacker and the plaintext of every frame a device sends, and in this class of product the code doing that job is not in the OS we can audit. The kernel bugs (Chapter 3) matter as instances of the same failure mode; the handshake attacks (Chapters 2-3) are that failure mode in its most consequential form. NuttX publishes a short list of CVEs, and the list is short partly because disclosures have been sparse and partly because the project counts differently from, say, the Linux kernel. Between May and December 2025 four CVEs landed in one codebase alone (Bluetooth UART, a font-conversion tool, an example XML-RPC application, and two filesystem bugs), which tells you both that auditing is happening and that the audit surface is not being watched continuously by fuzzers.

## Nota de âmbito: porquê WPA como mecanismo e não como exploração de rádio

> Este projeto é uma análise de segurança do sistema operativo de tempo real Apache NuttX e da pilha WPA que efetivamente protege os produtos Wi-Fi baseados nele. A decisão de não conduzir ataques WPA por rádio (KRACK e SAE/Dragonblood sobre o ar) foi deliberada e definitiva: esses ataques vivem no `wpa_supplicant` e no firmware de coprocessadores — componentes que não existem no NuttX upstream (verificado na árvore `apps/wireless`, que só contém bluetooth, ieee802154, iwpan, wapi e gs2200m, com o handshake a correr dentro do blob do módulo) — e a sua demonstração sem fios exigiria hardware Wi-Fi programável com injeção de frames e o toolchain xtensa, indisponíveis no prazo curto do projeto. Em alternativa, provámos o *mecanismo* dos dois ataques no ponto exato onde vivem, as máquinas de estado do supplicant, com modelos fiéis ao código upstream real (wpa.c 2.3 vs. atual; sae.c 2.3 vs. atual; curva e aritmética verdadeiras) e com medições estatísticas do próprio ciclo de caça do SAE. O capítulo correspondente (Capítulo 3) fecha com a análise da cadeia de fornecimento: em que árvore corre efetivamente o WPA de um produto NuttX, e por que razão essa resposta não está documentada em lado nenhum. O que foi possível reproduzir com provas de compilador está nos Estudos de Caso 1 e 2 (CVE-2025-35003 e CVE-2025-48768): as funções verbatim do kernel sob AddressSanitizer, com o código corrigido como controlo.

## Research questions

**RQ (KRACK):** How can a vulnerability in the WPA2 four-way handshake
undermine encryption without actually breaking the encryption algorithm?
The answer this report gives — in code, with a patched-vs-vulnerable
comparison — is in Chapter 3; the protocol machinery it presumes is in
Chapters 2.

## What we did

1. We enumerated the publicly disclosed NuttX CVEs from NVD and the Apache project's own security page, and classified them by subsystem, bug class and attack interface (Chapters 2).
2. We picked two CVEs to reproduce, chosen for demonstrability rather than severity: CVE-2025-35003 (buffer overflow in the Bluetooth UART driver) and CVE-2025-48768 (NULL write in the inode removal path). Chapter 3 explains the choice and shows the reproduction: the verbatim upstream functions compiled under AddressSanitizer with a small harness that replaces only the NuttX-specific glue.
3. We wrote a chapter on why NuttX is built the way it is, and where that design comes from in the Linux tradition, because the CVE list does not make sense without it (Chapters 2 and 3).
4. We proved the WPA2/KRACK and WPA3/SAE mechanisms at the supplicant's decision points with faithful upstream-code models, and mapped where that code actually executes in NuttX products (Chapters 5).
5. We compared NuttX's security engineering practice to Zephyr's, subsystem by subsystem: disclosure handling, fuzzing, static analysis, memory-protection posture (Chapter 7).
9. We close with what we think a critical-systems acquirer should take from all this (Chapters 7 and 8).

## Scope and honesty notes

The reproductions are host-harness reproductions, not full-system ones. They run the exact code the project shipped, with exact-sized heap allocations, under the same compiler class (LLVM with ASan); they do not run NuttX on silicon, and they cannot demonstrate register-level control-flow hijack. Where we claim consequences beyond the sanitizer trace (arbitrary code execution, fleet impact), the claim comes from the vendor advisory, and we cite it. Chapter 3 explains why the one CVE we could *not* reproduce cleanly (CVE-2025-48769, the `fs_rename` use-after-free, because "what is hard to reproduce" is itself information about the bug.
