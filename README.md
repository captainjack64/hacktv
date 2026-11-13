# hacktv – analogue TV transmitter for software-defined radios

hacktv generates complete analogue television signals (PAL, NTSC, SECAM,
D/D2-MAC and several historic standards) from a video file, a stream or a
built-in test card, and sends them to a HackRF, a SoapySDR device, an FL2K
USB-to-VGA adapter, or a file.

This repository is a fork of
[captainjack64/hacktv](https://github.com/captainjack64/hacktv), which itself
extends Philip Heron's original
[hacktv](https://codeberg.org/fsphil/hacktv) (formerly
`github.com/fsphil/hacktv`, now archived). At the time of writing this fork
carries no code changes of its own: the source is identical to
`captainjack64/hacktv` `master`. The aim of this fork is to run hacktv on a
Raspberry Pi 4, see [docs/raspberry-pi.md](docs/raspberry-pi.md).

**All credit for the original code goes to Philip Heron (fsphil). The
additional scrambling and conditional-access systems are the work of Alex
James (captainjack64) and the contributors named in the source files.**

## Features

Video standards (list them with `hacktv --list-modes`):

- PAL (B/G, I, D/K, M, N, FM, PAL-60), SECAM (L, D/K, B/G, I, FM), NTSC (M, I, FM, BS)
- D-MAC and D2-MAC (AM, FM or baseband)
- 819-line (System E), 405-line (System A), Baird 240-line and 30-line, NBTV 32-line
- NASA Apollo field-sequential colour and slow-scan mono, CBS 405-line field-sequential colour
- Each standard is available as a modulated RF signal (complex I/Q) and/or as unmodulated baseband (real)

Signal features:

- Teletext from TTI files, directories of TTI files or raw 42-byte packets (625 lines)
- Teletext subtitles on page 888, and burnt-in subtitles from the input file or an `.srt`
- NICAM 728 stereo, A2/Zweikanalton stereo, FM and AM audio subcarriers
- WSS (widescreen signalling), VITS test signals, VITC timecode, CEA/EIA-608 closed captions
- Analogue Copy Protection (Macrovision-like), Sound-in-Syncs (`dcsis`)
- Built-in test cards (PM5544, PM5644, FUBK, UEITM, colour bars) with a clock overlay
- Built-in channel logo overlay and on-screen timestamp
- Keyboard control during playback: pause, fast-forward and rewind (see below)

Scrambling and conditional access (details in
[docs/scrambling.md](docs/scrambling.md)):

- Videocrypt I, Videocrypt II and Videocrypt S, including many real Sky/TAC/Multichoice card modes
- Nagravision Syster (line shuffle) and Syster cut-and-rotate (incomplete)
- Discret 11 and Discret 14
- Cablecrypt (TV Cabo)
- Eurocrypt M, S, S2 and 3DES for D/D2-MAC, with single- or double-cut scrambling,
  maturity rating and pay-per-view
- Firmware images for home-made PIC16F84 and Funcard smart cards in [`cards/`](cards/)

What it does **not** do: DVB or any other digital TV standard.

## Quick start

```sh
# Debian, Ubuntu, Raspberry Pi OS
sudo apt-get install build-essential git pkg-config \
    libhackrf-dev libavutil-dev libavdevice-dev libavfilter-dev \
    libswresample-dev libswscale-dev libavformat-dev libavcodec-dev \
    libfreetype-dev libpng-dev zlib1g-dev

git clone https://github.com/itewreed/hacktv.git
cd hacktv/src
make -j4
sudo make install          # copies hacktv to /usr/local/bin
```

`libhackrf` is always required to build. SoapySDR and FL2K support are added
automatically if their development packages are installed. See
[docs/building.md](docs/building.md) for details, other distributions and the
Windows build.

Note that `apt-get install hacktv` on Debian installs the upstream version,
not this fork.

## Examples

```sh
# Write a PAL baseband signal of a video to a file
hacktv -o baseband.bin -m pal example.mkv

# Transmit the PM5544 test card on UHF channel 31 (PAL System I), 47 dB TX gain
hacktv -f 551250000 -m i -g 47 test:pm5544

# Same, with teletext
hacktv -f 551250000 -m i -g 47 --teletext src/demo.tti test

# Download and transmit the Teefax teletext service
svn checkout http://teastop.plus.com/svn/teletext/ teefax
hacktv -f 551250000 -m i -g 47 --teletext teefax test

# Play a playlist forever in random order, starting 10 minutes in
hacktv -f 551250000 -m i -g 47 --repeat --shuffle --position 10 *.mkv

# Videocrypt I, free access (any Videocrypt decoder, no card needed)
hacktv -f 551250000 -m i -g 47 --videocrypt free movie.mkv

# D2-MAC with Eurocrypt M and a channel logo
hacktv -f 551250000 -m d2mac-am -s 20250000 -g 47 --eurocrypt filmnet --logo filmnet movie.mkv

# Two channels at once on UHF 68 and 69 (PAL I)
hacktv -s 20000000 --offset -6.75e6 --level 0.5 --filter -o - test | \
  hacktv -s 20000000 -f 854e6 --offset 1.25e6 --level 0.5 --passthru /dev/stdin -g 47 --filter test

# Grab and transmit the local X11 display
hacktv -f 551.25e6 -m i -g 47 --ffmt x11grab --fopts framerate=25 ffmpeg::0

# Composite baseband through an FL2K VGA adapter, with analogue stereo audio
hacktv -o fl2k -m pal -s 13.5e6 --fl2k-audio stereo movie.mkv
```

The complete option reference is in [docs/usage.md](docs/usage.md), and
`hacktv --help` prints a summary.

### Playback controls

While a video file is playing, these keys work in the terminal:

| Key | Action |
|-----|--------|
| Space | Pause / resume (a pause icon and the position are shown on screen) |
| Right arrow | Skip forward 60 seconds |
| Left arrow | Skip back 60 seconds |

Seeking is ignored while paused. Press Ctrl+C to stop.

## Warning

The HackRF and other SDRs are not designed to be connected directly to AV
equipment. Make sure no DC voltage or control signal is fed back into the
SDR, and that the RF level is not too high for your receiver; use an
attenuator. Transmitting over the air without a licence is illegal in most
countries. Keep the signal on a cable.

## Documentation

| Document | Contents |
|----------|----------|
| [docs/building.md](docs/building.md) | Dependencies, build options, installing, Windows cross-build |
| [docs/usage.md](docs/usage.md) | All command-line options, inputs, outputs and sample rates |
| [docs/scrambling.md](docs/scrambling.md) | Videocrypt, Syster, Discret, Cablecrypt, Eurocrypt and smart cards |
| [docs/raspberry-pi.md](docs/raspberry-pi.md) | Running hacktv on a Raspberry Pi 4 |
| [docs/changelog.md](docs/changelog.md) | History of the captainjack64 additions |
| `src/hacktv.1` | Manual page |

## Links

- https://codeberg.org/fsphil/hacktv – original hacktv by Philip Heron
- https://sanslogic.co.uk/hacktv – original project page
- https://github.com/captainjack64/hacktv – the fork this repository is based on
- https://github.com/steeviebops/jhacktv-gui – cross-platform GUI for hacktv, written in Java

## Licence

GNU General Public License v3 or later, see [COPYING](COPYING).
