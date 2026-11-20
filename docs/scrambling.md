# Scrambling and conditional access

hacktv can reproduce many of the pay-TV systems used in Europe in the 1980s
and 1990s, so that original decoders and smart cards can be used again. The
mode names below are taken from the source code of this fork; `hacktv --help`
prints a summary.

Only one scrambling family can be active at a time. The exceptions are
Videocrypt I together with Videocrypt II, and Syster together with Syster
cut-and-rotate. Analogue Copy Protection cannot be combined with scrambling.

`--showecm` prints the control words and ECM data to the console, which helps
when debugging a card.

## Videocrypt I (`--videocrypt <mode>`)

Used by Sky and other satellite channels in the UK and Ireland. Each line is
cut at a pseudo-random point and the two halves are swapped. 625-line PAL
only; sample rates that are multiples of 14 MHz work best.

| Mode | Card needed |
|------|-------------|
| `free` | None, free access |
| `ppv` | Memory cards such as old phone cards (see below) |
| `jstv` | JSTV card |
| `sky02`, `sky03`, `sky04`, `sky05`, `sky06`, `sky07` | Sky card of that series, random control words |
| `sky09` | Sky series 09 card, random control words |
| `sky09nano` | Sky 09 card with nano commands still active (few cards have them) |
| `sky10` | Sky series 10 card, sample data from Sky One |
| `sky10ppv` | Sky series 10 card with PPV, sample data from a 1996 Tyson fight |
| `sky11` | Sky series 11 card (blue semi-oval logo), fixed control words from MTV |
| `sky12` | Sky series 12 card, sample data from Sky One |
| `skynz01`, `skynz02` | Sky New Zealand cards |
| `tac1`, `tac2` | The Adult Channel or Eurotica card |
| `xtea` | Funcard programmed with the supplied hex file, XTEA-encrypted control words |
| `dmx` | DMX card |
| `scast` | Sportscast card |

The `sky10` and `sky10ppv` modes emulate the Sky P10 card ASIC (reverse
engineered by Katy Coe). If a needed signature is not in the built-in table,
hacktv loads `videocrypt10-data.bin` (64 MB) from the current directory. That
file is not part of this repository.

Card management:

- `--enableemm <serial>` and `--disableemm <serial>` send an EMM that switches
  a card on or off. Give the first 8 digits of the card number. Supported by
  the modes that carry EMMs (`sky06`, `sky07`, `sky09`, `sky09nano`,
  `skynz01`, `skynz02`, `tac1`, `tac2`).
- `--showserial` shows the serial number of the inserted card on screen.

Pay-per-view with memory cards (`ppv`): the card serial and key are stored in
`_ppv_card_data[]` in `src/videocrypt.c`. The serial is bits 0–39 and the key
bits 40–49 of the card, with each byte bit-reversed. If you do not know the
key, `--findkey` tries all values; watch the screen until the picture clears,
which can take up to 45 hours. The start values are `_ppv_card_data[5]` and
`[6]` in `videocrypt.c`, so an interrupted search can be resumed.

## Videocrypt II (`--videocrypt2 <mode>`)

The European variant of Videocrypt with a higher VBI data rate, used by
Multichoice. It can run at the same time as Videocrypt I, so one signal
can be watched with both decoder types. In that case Videocrypt II `free`
needs Videocrypt I `free` as well.

| Mode | Card needed |
|------|-------------|
| `free` | None |
| `conditional` | Multichoice card, or a PIC16F84 card with `cards/pic/Videocrypt2-PIC16F84.hex` |

## Videocrypt S (`--videocrypts <mode>`)

Used by the short-lived BBC Select service. It shuffles lines instead of
cutting them. Audio inversion is not implemented.

| Mode | Card needed |
|------|-------------|
| `free` | None |
| `conditional` | BBC Select card (does not work yet) |

## Nagravision Syster (`--syster <mode>`)

Used by Canal+ and Premiere. Lines are shuffled within each field.
625-line modes only.

| Mode | Key needed | Default table |
|------|------------|---------------|
| `premiere-fa` | Premiere, free access | 1 |
| `premiere-ca` | Premiere, subscription access | 1 |
| `cfrfa` | Canal+ France, free access | 2 |
| `cfrca` | Canal+ France, subscription access | 2 |
| `cplfa` | Canal+ Poland, free access | 1 |
| `cesfa` | Canal+ Spain, free access | 1 |
| `chorfa` | Canal+ Horizons, free access | 2 |
| `ntvfa` | HTB+ (NTV Plus) Russia, free access | 2 |

All modes use random control words. `--key-table-1` and `--key-table-2`
override the permutation table. A PIC16F84 "key" can be made with
`cards/pic/Syster-PIC16F84.hex` and your own keys.

`--systercnr <mode>` enables the cut-and-rotate variant, which only works
with Premiere decoders and is incomplete. Use a sample rate that is a multiple
of the Syster line rate, e.g. `-s 17750000` (4 × 4 437 500). It can be
combined with `--syster`; the `--syster` mode is used if they differ.

`--systeraudio` inverts the audio spectrum around 12.8 kHz, which some
decoders expect.

## Discret 11 (`--d11 <mode>`)

The predecessor of Syster: each line is delayed by one of three amounts,
giving a jagged picture. Works with Discret decoders and with Syster decoders.
It takes the Syster mode names above (a Syster decoder needs a matching key).
Use `--systeraudio` if the decoder inverts the audio.

## Discret 14 (`--d14`)

Line-delay scrambling with its own VBI data on lines 24, 310, 336 and 622.
625-line modes only, no mode argument.

## Cablecrypt (`--cablecrypt-tvcabo`)

Reproduces the scrambling of the Portuguese cable operator TV Cabo, based on
off-air recordings: data lines in the VBI, luma inversion at scene changes,
chroma changes and displaced horizontal sync in random blocks of lines.
625-line modes only.

## Eurocrypt (`--eurocrypt <mode>`)

The conditional-access system of D-MAC and D2-MAC. hacktv supports
Eurocrypt M, S, S2 and the 3DES variant. If neither `--single-cut` nor
`--double-cut` is given, single-cut scrambling is used. Add
`--scramble-audio` to scramble the sound as well.

| Mode | Type | Channel |
|------|------|---------|
| `bbcprime` | M | BBC Prime |
| `cplusfr` | M | Canal+ France 4:3 |
| `cplusfr169` | M | Canal+ France 16:9 |
| `ctv` | M | CTV |
| `filmnet` | M | FilmNet |
| `multivisio` | M | Multivisio |
| `tv3` | M | TV3 |
| `tv1000` | M | TV1000 (Viasat) |
| `tvcable` | M | TV Cable |
| `tvplus` | M | TV Plus (Netherlands) |
| `visiopass` | M | Visiopass |
| `teletv` | S | Tele-TV |
| `nrk` | S2 | NRK |
| `tv2` | S2 | TV2 Norway |
| `ctvs` | S2 | CTV |
| `eros` | S2 | Eros |
| `rdv` | S2 | RDV |
| `tvs` | S2 | TV-S (Denmark) |
| `cplus` | 3DES | Canal+ Nordic |

hacktv also sends EMMs for the modes that have management keys. MultiMac
style cards can be used as well.

Extra options for official cards:

- `--ec-mat-rating <0-15>` sets the maturity rating (0 disables it).
- `--ec-ppv <programme,cost>` enables pay-per-view, e.g. `--ec-ppv 12,54` for
  programme 12 costing 54 tokens. Once a programme is enabled on a card it stays
  enabled. A cost of 0, or no value, works with most Eurocrypt M cards without
  credit.

## Card images in `cards/`

| File | Use |
|------|-----|
| `pic/Videocrypt-Sky-Mode-PIC16F84.hex` | Videocrypt Sky mode card |
| `pic/Videocrypt-TAC-Mode-PIC16F84.hex` | Videocrypt TAC mode card |
| `pic/Videocrypt2-PIC16F84.hex` | Videocrypt II `conditional` |
| `pic/Syster-PIC16F84.hex` | Syster and Discret 11 key |
| `pic/Eurocrypt-AU-mm215pic.hex`, `pic/Eurocrypt-AU-mm215eeprom.hex` | MultiMac card that accepts Eurocrypt EMM updates (PIC and EEPROM images) |
| `funcard/Videocrypt-All-Modes-ATMEL.hex`, `.eep` | Funcard (Atmel AVR) for the Videocrypt modes, including `xtea` |

The PIC16F84 images also fit old pirate D2-MAC cards known as "Goldwafer" or
"MultiMac"; for the Videocrypt images only the PIC needs flashing, the external
EEPROM is not used.
