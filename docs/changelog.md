# History of the captainjack64 additions

This is the change history that the captainjack64 fork kept in its README,
lightly edited. Newer changes (2022 onwards) are only recorded in the git
log; the main ones are listed first. Some option names have changed since the
older entries were written; where that is the case the current name is given
in brackets. The current options are described in [usage.md](usage.md) and
[scrambling.md](scrambling.md).

## Recent changes (from the git log)

- **2026-10** – Fast-forward and rewind while playing a video (right and left
  arrow keys, 60 seconds), with an on-screen icon and position. Cablecrypt
  (TV Cabo) scrambling (`--cablecrypt-tvcabo`). Sky New Zealand and
  `test:ueitm` fixes.
- **2026-09** – Build against libpng 1.6.
- **2026-03** – Discret 14 scrambling (`--d14`).
- **2026-01** – Videocrypt Sky P10 card emulation for `sky10`/`sky10ppv`
  (ASIC reverse engineered by Katy Coe). Merged from upstream: PLN/CPS test
  card replay (`--cps`), mono FL2K analogue audio.
- **2025-11** – Windows build updated to current dependency versions.
- **2025-03** – Sportscast Videocrypt card (`scast`).
- **2024-01** – DMX Videocrypt key (`dmx`), JSTV fix.

## Older entries

**2021-11-10** – Reworked the Videocrypt routines for easier reading and for
adding new modes. The `tac1` and `tac2` modes were replaced with a single `tac`
mode. [Today the source again has `tac1` and `tac2` and no `tac`.]

**2021-10-28** – Videocrypt nano commands for Sky 09 cards. Only works with
official Sky 09 cards that still have nanos active, which few do.
Enabled with `--sky09nano` [now `--videocrypt sky09nano`].

**2021-10-08** – Pay-per-view for Eurocrypt, for official cards with some
credit loaded. Enabled with `--ec-ppv <programme,cost>`, e.g. `--ec-ppv 12,54`
for programme 12 costing 54 tokens. Once a programme is enabled it stays
enabled. A cost of 0, or no value, works on most Eurocrypt M cards without
credit.

**2021-09-25** – Eurocrypt maturity rating for official cards, 0 (off) to 15:
`--ec-mat-rating <0-15>`.

**2021-03-26** – Teletext subtitles on page 888, viewable with teletext or by
selecting "English subtitles" on a D/D2-MAC decoder. Enabled with
`--txsubtitles` [now `--tx-subtitles`].

**2021-03-13** – `--downmix` converts 5.1 and other layouts to stereo;
`--volume` changes the volume.

**2021-02-12** – No more external files at runtime (fonts and PNG images are
built in). PM5544, UEITM and FUBK test cards (`test:pm5544` etc.). Many FFmpeg
filters replaced with native code.

**2021-01-06** – Much improved Syster cut-and-rotate (credit to fsphil). Syster
line shuffling and cut-and-rotate can run at the same time.

**2020-12-16** – Rudimentary Syster cut-and-rotate, Premiere decoders only.
Use `--systercnr` with a multiple of the Syster line sampling rate, e.g.
17750000 (4 × 4437500). References to "Smartcrypt" removed.

**2020-11-06** – Option to choose the Syster permutation table
(`--key-table-1`, `--key-table-2`).

**2020-10-23** – Eurocrypt changes, including EMMs for Eurocrypt M. To test,
program a card with the supplied MultiMac PIC files and run the `tv3update`
mode; the card updates within 30 seconds. [`tv3update` no longer exists; see
the mode list in scrambling.md.]

**2020-08-05** – HTB+ Russia for Syster. Videocrypt PPV mode for old memory
(phone) cards: dump the card or brute-force the key with `--findkey` (can take
up to 45 hours), show the serial with `--showserial`. Details in
scrambling.md.

**2020-07-24** – `--letterbox` and `--pillarbox` for 4:3 screens.

**2020-05-13** – Enable and disable Multichoice Videocrypt II cards
(experimental, at your own risk).

**2020-04-24** – Eurocrypt S2 with more cards and modes (experimental).

**2020-04-21** – Eurocrypt double-cut scrambling for MAC modes
(`--double-cut`).

**2020-04-17** – Subtitles from the container or an external `.srt`
(`--subtitles [index]`). Eurocrypt M scrambling for MAC modes
(`--eurocrypt <mode>`).

**2020-02-07** – Enable or disable Sky 07 and 09 cards with
`--enableemm`/`--disableemm <first 8 digits of the card number>`.
`--showecm` for conditional-access debugging. Videocrypt I and II can be used
together in most modes. Syster updates.

**2020-01-09** – Removed the Syster `pirate` option; use `premiere-fa` with the
updated hex file.

**2020-01-07** – All Syster modes use random control words.

**2020-01-06** – Canal+ Poland and Canal+ France free-access (audience 11)
Syster modes. D11 fixed.

**2020-01-02** – Syster DES for random control words. New PIC hex file; use your
own keys.

**2019-12-27** – Videocrypt II conditional access, for Multichoice Central
Europe cards or the included PIC16F84 hex file. The old `--key` option was
removed [modes are now given to `--videocrypt`].

**2019-12-11** – Sky series 10 cards: `sky10`, and `sky10ppv` with samples from
the 1996 Tyson fight.

**2019-12-06** – Sky 07 (and maybe 06) cards: `sky07`.

**2019-07-26** – Sky 09 cards (`sky09`) and Sky 11 cards (`sky11`).

**2019-05-17** – Discret 11 in audience 7 / free-access mode (`--d11`). PIC hex
for Syster and for D11 in a Syster decoder.

**2019-04-30** – Holding screen while seeking to `--position`. XTEA mode for
Videocrypt I (`xtea`) with a Funcard hex file.

**2019-04-25** – Merged Syster hardware support from upstream. Control word
change for Videocrypt TAC tested on a real card. Widescreen videos are
letterboxed instead of stretched. New options `--position <minutes>`,
`--timestamp` and `--logo <name>`.

**2019-04-07** – PAL FM deviation changed and default level reduced to 0.8.
Videocrypt conditional mode with Sky 09, Sky 11 and TAC cards. Hex files for
PIC16F84 cards (also known as "Goldwafer" or "MultiMac" cards).
