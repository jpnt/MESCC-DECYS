## Why WPA2, and why now

This project follows the DECYS research style "Security Analysis of
Existing Systems" [@brief]: identify real flaws in a deployed system and
demonstrate them. WPA2 is the most deployed link-layer security protocol
in existence, and for a decade it carried a family of vulnerabilities
that no cipher change could fix, because the cipher was never the
problem: KRACK (2017) forced nonce reuse in AES-CCMP by replaying a
handshake message, and Dragonblood (2019) did the same to WPA3's SAE
handshake through reflection and timing. Between them they define the
subject of this report: how state machines leak what mathematics keeps.

## Nota de âmbito (scope note, PT)

> O ataque em si não é conduzido sobre o ar: reproduzir KRACK ou
> Dragonblood por rádio exige hardware de injeção e um kernel Linux com
> `mac80211_hwsim`, indisponíveis na máquina usada neste trabalho (arm64,
> ver Capítulo 5). Demonstramos antes o *mecanismo* no ponto exato onde
> ele vive — a máquina de estados do `wpa_supplicant` — com modelos fiéis
> ao código oficial a montante (versão 2.3 vulnerável vs. versão atual
> corrigida, com *hashes* sha256 fixados), e medimos a fuga temporal do
> ciclo de caça SAE com aritmética real em P-256. O procedimento completo
> do laboratório de ataque (`krackattacks-scripts` + `wifi-framework` +
> Wireshark com PSK) está documentado passo a passo no Capítulo 5 para
> execução em x86/Kali. Nenhum ataque foi dirigido contra uma rede real;
> o resultado esperado e relatado é o contraste vulnerável/patched.

## Research question

**How can a vulnerability in the WPA2 four-way handshake undermine
encryption without actually breaking the encryption algorithm?** The
answer is given in code (Chapter 3), with the patched-versus-vulnerable
comparison the plan requires; the protocol machinery it presumes is
Chapter 2.

## What we did

1. Built a faithful model of the supplicant's 4-way receiver from the
   official `wpa_supplicant` 2.3 release (w1.fi tarball, sha256 recorded)
   and its patched successor, and executed the key-reinstallation
   consequence: a replayed Message 3 resets the transmit counter, the
   keystream is reused, and a known ARP frame yields a second frame's
   plaintext. The patched model refuses the reinstall (`make krack`).
2. Modelled the WPA3/SAE reflection DoS on a real, point-counted curve
   (vulnerable: 5/5 livelocked rounds; patched: guard drops the echo),
   and *measured* the SAE hunt loop's timing leak with a seeded replica
   of the upstream loop over NIST P-256 arithmetic (`make sae`).
3. Analysed the root cause at protocol level (the Install bit's meaning
   versus its transport) against the formal analysis of Cremers et al.
   [@cremers2020], and mapped the security implications honestly:
   keystream reuse versus the TKIP and all-zero-key edge cases.
4. Audited where this code actually ships: the vendor-SDK path
   (ESP-IDF's supplicant port carries no base revision; KRACK-era fixes
   arrive as silent backports; Wi-Fi crypto on RTOS-class products runs
   inside closed blobs) — evidence checked in under `lab/`.
5. Documented the plan's reference lab step by step (`krackattacks-scripts`,
   `mac80211_hwsim`, `wifi-framework`, Wireshark PSK decryption) and
   reported our negative result honestly: this machine has no
   hwsim-capable kernel, so the attack-side capture is an x86 follow-up.
6. Wrote mitigations and evolution (idempotent key installation,
   uniform-cost loops, WPA3/SAE with its real scope), the critical
   evaluation the plan asks for, and the conclusion.

## Scope and honesty notes

The reproductions are receiver-side models: the vulnerable branch, the
key reset and the consequence are computed exactly as the upstream code
does, and the patched control is the guard string from the same file.
What the models do not do is radiate frames; that step belongs to the
documented hwsim lab. Where we rely on the original research instead of
our own runs (the TKIP MICAR attack, the Android/Linux zero-key cases,
the cache-attack micro-architecture), we cite and say so. The SAE
timing result is a *measured property of the upstream loop*, not a
cache attack performed here. Everything executable in the report
re-runs byte-identically from a clean checkout: `make krack`, `make
sae`, `make report`, `make slides`.
