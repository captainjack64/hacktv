# Running hacktv on a Raspberry Pi 4

The goal of this fork is a small, always-on analogue TV source built around a
Raspberry Pi 4, in the spirit of
[raspi-teletext](https://github.com/ali1234/raspi-teletext). This page
describes what works today and what has not been verified yet.

> **Status:** hacktv builds from portable C (no x86-specific code), and the
> dependencies are all packaged for Raspberry Pi OS. Running it on a Pi 4 has
> not yet been tested with this fork. Treat the performance notes below as
> starting points, and please report results.

## How hacktv differs from raspi-teletext

raspi-teletext does not create a video signal. It takes over a few VBI lines
of the Pi's own composite video output and inserts teletext packets there,
while the GPU draws the picture.

hacktv generates the whole signal (sync, picture, colour, sound
subcarriers, teletext and scrambling) in software, sample by sample. It has no
driver for the Pi's built-in composite output, so the signal has to leave the
Pi through one of hacktv's outputs:

| Output | What you get | Notes |
|--------|--------------|-------|
| HackRF One (`-o hackrf`) | Modulated RF on a UHF/VHF channel, to a TV's aerial input | Needs RF modes such as `-m i`. Use an attenuator and keep it on a cable |
| FL2K USB-to-VGA adapter (`-o fl2k`) | Composite baseband on the red pin of the VGA port, optional audio on green/blue | Needs baseband modes such as `-m pal`. 0.7 V p-p is too low, so add a video amplifier. Plug it into a blue USB 3 port |
| SoapySDR device (`-o soapysdr`) | RF, like the HackRF | Needs `libsoapysdr-dev` at build time |
| File or pipe (`-o file`) | Raw samples | For testing, or to feed other tools |

## Preparing the Pi

Use the 64-bit Raspberry Pi OS (Bookworm or newer), Lite is enough. Then:

```sh
sudo apt-get update
sudo apt-get install build-essential git pkg-config \
    libhackrf-dev hackrf libavutil-dev libavdevice-dev libavfilter-dev \
    libswresample-dev libswscale-dev libavformat-dev libavcodec-dev \
    libfreetype-dev libpng-dev zlib1g-dev
# for an FL2K adapter
sudo apt-get install libosmo-fl2k-dev osmo-fl2k

git clone https://github.com/itewreed/hacktv.git
cd hacktv/src
make -j4 EXTRA_CFLAGS="-mcpu=cortex-a72"
sudo make install
```

`-mcpu=cortex-a72` tunes the build for the Pi 4 CPU; it is optional. The
`hackrf` package installs udev rules so hacktv can use the HackRF without
root; for the FL2K you may need to add a rule yourself or run as root. Check the device with `hackrf_info` before starting hacktv.

## First test

Start with the built-in test card, which needs no video decoding:

```sh
# HackRF, PAL System I, UHF channel 31
hacktv -f 551250000 -m i -g 30 test:pm5544

# FL2K, PAL composite on the red VGA pin
hacktv -o fl2k -m pal -s 13.5e6 test:pm5544
```

If the picture breaks up, or the HackRF output prints `U` characters or
`hackrf: N underruns` on the console, the Pi is not keeping up. Things to try, roughly in order:

- Lower the sample rate. The default is 20.25 MHz; 16 MHz is enough for PAL
  with FM and NICAM sound, and baseband-only PAL works at 13.5 MHz.
- Turn off what you do not need: `--nonicam`, `--noaudio`, `--filter` (off by
  default, leave it off).
- Pre-convert videos to standard definition (720×576, 25 fps for PAL) so
  FFmpeg has less decoding and scaling to do.
- Cool the Pi properly; it throttles at high temperatures.

## Teletext, as with raspi-teletext

hacktv reads teletext from `.tti` page files, from a directory of them, or
from a stream of raw 42-byte packets. The packet format is the one used by
raspi-teletext, so packet generators written for it can feed hacktv too:

```sh
# Pages from a directory of .tti files
hacktv -f 551250000 -m i -g 30 --teletext /home/pi/pages test

# Raw packets through a named pipe
mkfifo /tmp/teletext
your-packet-generator > /tmp/teletext &
hacktv -f 551250000 -m i -g 30 --teletext raw:/tmp/teletext movie.mkv
```

`--teletext raw:-` reads from stdin, but while a video file is playing hacktv
also reads stdin for the playback keys, which would consume teletext bytes.
Use a named pipe or a file when the input is a video.

## Running as a service

A systemd unit starts the channel at boot. Example
`/etc/systemd/system/hacktv.service`:

```ini
[Unit]
Description=hacktv analogue TV channel
After=network.target

[Service]
# Change to your user name
User=pi
ExecStart=/bin/sh -c 'exec /usr/local/bin/hacktv -f 551250000 -m i -g 30 --repeat --shuffle --teletext /home/pi/pages /home/pi/videos/*.mkv'
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

The command runs through `/bin/sh` because systemd does not expand `*`
itself. Enable it with `sudo systemctl enable --now hacktv`.

## Open points

- Measure CPU load and the highest stable sample rate on a Pi 4 for the
  HackRF and FL2K outputs.
- Check whether the FL2K reaches the needed USB 3 bandwidth on the Pi 4.
- A driver for the Pi's built-in composite output is not part of hacktv.
