# Using hacktv

```
hacktv [options] input [input...]
```

hacktv reads one or more inputs in order, encodes them into the selected TV
standard and writes the samples to the selected output. With `--repeat` the
list loops forever; with `--shuffle` it is played in random order.

`hacktv --help` prints a short summary of the options below.
`hacktv --list-modes` prints all TV standards (`--json` for machine-readable
output). Numbers accept scientific notation, so `-f 551.25e6` and
`-f 551250000` are the same.

## Inputs

| Input | Description |
|-------|-------------|
| `test` or `test:pm5544` | Philips PM5544 test card with clock (default test card) |
| `test:pm5644` | Philips PM5644 16:9 test card |
| `test:fubk` | German FuBK test card with clock |
| `test:ueitm` | Soviet UEIT test card (no clock) |
| `test:colourbars` | Colour bars |
| `ffmpeg:<file or URL>` | Anything FFmpeg can open: files, network streams, capture devices |
| `<file or URL>` | Same as `ffmpeg:`; this is assumed when no prefix is given |

The image test cards are only drawn in 576-line (625-line) modes. In other
modes, the test input shows colour bars with a "HACKTV" caption. The test
input also plays a 1 kHz tone.

### FFmpeg input options

| Option | Description |
|--------|-------------|
| `--ffmt <format>` | Force the input format, e.g. `x11grab`, `v4l2`, `alsa` |
| `--fopts <opt=value[:opt2=value]>` | Pass options to the FFmpeg demuxer |
| `-p, --position <minutes>` | Start playback this many minutes into the file |

### Playback controls

While a file is playing, Space pauses and resumes, and the right and left
arrow keys skip forward and back by 60 seconds. An icon and the current
position are shown on screen for a few seconds. Seeking is ignored while
paused.

## Outputs

Select the output with `-o`. The default is `hackrf`. A value without a
known prefix is treated as a file name.

| Output | Description |
|--------|-------------|
| `-o hackrf[:<serial>]` | HackRF One. RF (complex) modes only, unless a HackDAC baseband module is fitted |
| `-o soapysdr[:<args>]` | Any SoapySDR device, e.g. `-o soapysdr:driver=lime` |
| `-o fl2k[:<device index>]` | FL2000 USB-to-VGA adapter (osmo-fl2k) |
| `-o file:<name>` or `-o <name>` | Raw samples to a file; `-` writes to stdout |

### RF options (HackRF and SoapySDR)

| Option | Description |
|--------|-------------|
| `-f, --frequency <Hz>` | Centre frequency. HackRF range is 0 to 7250 MHz. For RF modes this is the vision carrier |
| `-g, --gain <dB>` | HackRF: TX VGA (IF) gain, 0–47 dB. SoapySDR: TX gain. Default 0 |
| `-a, --amp` | HackRF: enable the TX RF amplifier |
| `-A, --antenna <name>` | SoapySDR: select the antenna |

### FL2K options

| Option | Description |
|--------|-------------|
| `--fl2k-audio <mode>` | `none` (default), `mono`, `stereo` or `spdif` |

The three VGA channels are used as follows:

- Red: baseband video, or the I channel of a complex signal
- Green: Q channel, or left analogue audio, or nothing
- Blue: right/mono analogue audio, or S/PDIF digital audio, or nothing

With `--s-video` the chroma signal is sent on the second channel. The FL2K
produces 0.7 V peak to peak, which is too low for correct composite video; the
picture will look dark without an amplifier. Analogue audio has 8-bit
resolution with the lower 8 bits delta-sigma modulated in the LSB, so use a
~16 kHz low-pass filter. S/PDIF is fixed at 16-bit, 32 kHz, which not every
decoder accepts.

### File options

| Option | Description |
|--------|-------------|
| `-t, --type <type>` | Sample format: `uint8`, `int8`, `uint16`, `int16` (default), `int32`, `float` |

Baseband modes write real samples, RF modes write interleaved I/Q pairs.

## General options

| Option | Default | Description |
|--------|---------|-------------|
| `-m, --mode <name>` | `i` | TV standard, see `--list-modes` and the table below |
| `-s, --samplerate <Hz>` | 20.25 MHz | Output sample rate |
| `--pixelrate <Hz>` | sample rate | Video pixel rate, if it should differ from the sample rate |
| `-l, --level <value>` | 1.0 | Output level multiplier |
| `-D, --deviation <Hz>` | per mode | Override the FM peak deviation of FM modes |
| `-G, --gamma <value>` | per mode | Override the gamma correction |
| `-i, --interlace` | off | Update the picture every field instead of every frame |
| `-r, --repeat` | off | Repeat the input list forever |
| `--shuffle` | off | Play the inputs in random order |
| `-v, --verbose` | off | More console output |
| `--version` | | Print the version and exit |

The number of samples per line is rounded to a whole number, which may cause
a small frame-rate error. The sample rate must be high enough for the video
and all audio subcarriers. Good values:

| Mode family | Sample rate |
|-------------|-------------|
| PAL | 16 MHz, or 20.25 MHz (default). Videocrypt prefers multiples of 14 MHz |
| NTSC | 13.5 MHz |
| D/D2-MAC | 20.25 MHz (may not work with every HackRF) |
| Syster cut-and-rotate | multiples of 4.4375 MHz, e.g. 17.75 MHz |

### TV standards

Modes that `--list-modes` describes as "AM (complex)", "FM (complex)" or
"VSB (complex)" are RF modes for SDRs. Modes described as "unmodulated
(real)", such as `pal`, `secam`, `ntsc` and `d2mac`, are composite baseband
signals for the FL2K, a HackDAC or a file.

| Mode | Standard |
|------|----------|
| `i`, `b`, `g`, `pal-d`, `pal-k`, `pal-m`, `pal-n`, `pal-fm` | PAL RF variants |
| `pal`, `525pal`, `625pal-n`, `525pal-m`, `pal60-i`, `pal60` | PAL baseband and PAL-60 |
| `l`, `d`, `k`, `secam-i`, `secam-b`, `secam-g`, `secam-fm`, `secam` | SECAM |
| `m`, `ntsc-i`, `ntsc-fm`, `ntsc-bs`, `ntsc` | NTSC |
| `d2mac-am`, `d2mac-fm`, `d2mac`, `dmac-am`, `dmac-fm`, `dmac` | D2-MAC and D-MAC |
| `e`, `819` | French 819 lines |
| `a`, `ntsc-a`, `405-i`, `405`, `ntsc-405` | British 405 lines |
| `240-am`, `240`, `30-am`, `30`, `nbtv-am`, `nbtv` | Baird 240/30 lines, NBTV 32 lines |
| `apollo-fsc-fm`, `apollo-fsc`, `apollo-fm`, `apollo` | NASA Apollo colour and mono |
| `m-cbs405`, `cbs405` | CBS field-sequential colour |

## Picture options

| Option | Description |
|--------|-------------|
| `--letterbox` | Fit widescreen content inside a 4:3 picture with black bars |
| `--pillarbox` | Zoom widescreen content to fill a 4:3 picture. Cannot be combined with `--letterbox` |
| `--logo <name>` | Overlay a built-in logo: `hacktv`, `cartoonnetwork`, `tv1000`, `filmnet1`, `filmnetplus`, `canal+`, `eurotica`, `mtv`, `tac`, `filmnet`, `multichoice`, `skyone`, `sky` |
| `--timestamp` | Overlay the playback time |
| `--nocolour`, `--nocolor` | Disable the colour subcarrier (PAL, SECAM, NTSC) |
| `--s-video` | Put the colour subcarrier on a second channel (PAL, SECAM, NTSC baseband) |
| `--invert-video` | Invert sync and white levels of the composite signal |
| `--secam-field-id` | Send SECAM field identification lines |
| `--secam-field-id-lines <1-9>` | Number of identification lines per field (default 9) |
| `--fit`, `--min-aspect`, `--max-aspect` | Accepted for compatibility with upstream, but `--fit` is disabled in this fork; use `--letterbox` or `--pillarbox` |

Without either option, 16:9 sources are padded to the 16:9 frame rather than stretched.

## Audio options

| Option | Description |
|--------|-------------|
| `--volume <value>` | Scale the audio, e.g. `0.5` or `1.5` |
| `--downmix` | Downmix 5.1 and other multichannel audio to stereo |
| `--noaudio` | Disable all audio subcarriers |
| `--nonicam` | Disable the NICAM subcarrier |
| `--a2stereo` | Use A2/Zweikanalton stereo instead of NICAM |
| `--sis dcsis` | Sound-in-Syncs (625 lines) |

D/D2-MAC audio:

| Option | Description |
|--------|-------------|
| `--mac-audio-stereo` / `--mac-audio-mono` | Stereo (default) or mono |
| `--mac-audio-high-quality` / `--mac-audio-medium-quality` | 32 kHz (default) or 16 kHz |
| `--mac-audio-companded` / `--mac-audio-linear` | Companded (default) or linear coding |
| `--mac-audio-l1-protection` / `--mac-audio-l2-protection` | First (default) or second level error protection |
| `--chid <id>` | Channel ID |

## Data services

| Option | Description |
|--------|-------------|
| `--teletext <path>` | Teletext from a `.tti` file, or every file in a directory. `raw:<file>` reads 42-byte packets, `raw:-` reads stdin. 625-line modes only, lines 7–22 and 320–335 |
| `--tx-subtitles [index]` | Show subtitles as teletext on page 888. On a D/D2-MAC decoder select "English subtitles" |
| `--subtitles [index]` | Burn subtitles into the picture |
| `--wss <mode>` | Widescreen signalling, 625 lines: `4:3`, `14:9-letterbox`, `14:9-top`, `16:9-letterbox`, `16:9-top`, `16:9+-letterbox`, `14:9-window`, `16:9`, `auto` |
| `--vits` | VITS test lines (525 and 625 lines) |
| `--vitc` | VITC timecode (525 and 625 lines) |
| `--cc608` | Pass CEA/EIA-608 closed captions through (525 and 625 lines) |
| `--acp` | Analogue Copy Protection (525 and 625 lines, not together with scrambling) |

For both subtitle options the optional index selects a subtitle stream in the
input. If the file has no subtitle stream, hacktv loads an `.srt` file with
the same base name next to the video (for `movie.mkv`, `movie.srt`).

## Scrambling and conditional access

| Option | Description |
|--------|-------------|
| `--videocrypt <mode>` | Videocrypt I |
| `--videocrypt2 <mode>` | Videocrypt II (can run alongside Videocrypt I) |
| `--videocrypts <mode>` | Videocrypt S |
| `--enableemm <serial>` / `--disableemm <serial>` | Send an EMM to switch a Videocrypt card on or off (first 8 digits of the card number) |
| `--showserial` | Videocrypt: show the card serial number on screen |
| `--findkey` | Videocrypt `ppv` mode: brute-force the card key |
| `--showecm` | Print control words and ECM data on the console |
| `--syster <mode>` | Nagravision Syster line shuffling |
| `--systercnr <mode>` | Syster cut-and-rotate (incomplete) |
| `--key-table-1` / `--key-table-2` | Syster permutation table |
| `--systeraudio` | Invert the audio spectrum (Syster, Syster CnR, Discret 11) |
| `--d11 <mode>` | Discret 11 |
| `--d14` | Discret 14 |
| `--cablecrypt-tvcabo` | Cablecrypt as used by TV Cabo |
| `--eurocrypt <mode>` | Eurocrypt for D/D2-MAC (implies single-cut if no cut mode is given) |
| `--single-cut` / `--double-cut` | D/D2-MAC line cut-and-rotate scrambling |
| `--scramble-audio` | Scramble D/D2-MAC audio |
| `--ec-mat-rating <0-15>` | Eurocrypt maturity rating |
| `--ec-ppv [prog,cost]` | Eurocrypt pay-per-view |
| `--nodate` | Eurocrypt: set the date-verification bit in the ECM (experimental) |

Mode names and card requirements are listed in
[scrambling.md](scrambling.md). Only one scrambling family can be used at a
time, except Videocrypt I + II and Syster + Syster CnR.

## Signal processing and test options

| Option | Description |
|--------|-------------|
| `--filter` | Experimental VSB filter for RF modes |
| `--swap-iq` | Swap I and Q to invert the spectrum (complex modes) |
| `--offset <Hz>` | Shift the signal in frequency (complex modes) |
| `--passthru <file>` | Add an int16 complex signal from a file, e.g. a second hacktv |
| `--raw-bb-file <file>` | Replace the active video with raw int16 baseband samples from a file (looped) |
| `--raw-bb-blanking <value>` | Blanking level of the raw baseband file (default 0) |
| `--raw-bb-white <value>` | White level of the raw baseband file (default 32767) |
| `--cps <file>` | Replay a PLN/CPS test card file |

## Combining two channels

hacktv can mix several channels into one RF stream with `--offset` and
`--passthru`. The first instance writes a complex signal to stdout, and the
second adds it to its own signal:

```sh
hacktv -s 20000000 --offset -6.75e6 --level 0.5 --filter -o - test | \
  hacktv -s 20000000 -f 854e6 --offset 1.25e6 --level 0.5 \
         --passthru /dev/stdin -g 47 --filter test
```
