# Building hacktv

hacktv is a single C program built with GNU make. All sources are in
[`src/`](../src). There is no configure step: the Makefile asks `pkg-config`
which optional libraries are installed and enables the matching output
drivers.

## Dependencies

Always required:

| Library | Debian/Ubuntu package | Used for |
|---------|-----------------------|----------|
| libhackrf | `libhackrf-dev` | HackRF output. The Makefile links it unconditionally, so it is needed even if you never use a HackRF |
| FFmpeg (libavcodec, libavformat, libavdevice, libavfilter, libavutil, libswscale, libswresample) | `libavcodec-dev libavformat-dev libavdevice-dev libavfilter-dev libavutil-dev libswscale-dev libswresample-dev` | Decoding video, audio and subtitles |
| FreeType 2 | `libfreetype-dev` | Text overlays (clock, timestamp, subtitles) |
| libpng 1.6 | `libpng-dev` | Built-in logos and test cards |
| zlib | `zlib1g-dev` | Linked explicitly (`-lz`), needed by libpng |
| pthreads, libm | part of the C library | |

Optional, detected automatically:

| Library | Debian/Ubuntu package | Enables |
|---------|-----------------------|---------|
| SoapySDR | `libsoapysdr-dev` | `-o soapysdr` output (LimeSDR, PlutoSDR, USRP and others) |
| osmo-fl2k | `libosmo-fl2k-dev` | `-o fl2k` output through FL2000 USB-to-VGA adapters |

If a driver is not compiled in, selecting it prints for example
`FL2K support is not available in this build of hacktv.`

Build tools: `gcc`, `make`, `pkg-config` and `git` (the version string is
taken from `git log` and `git describe`, so build from a git checkout).

### Debian, Ubuntu, Raspberry Pi OS

```sh
sudo apt-get update
sudo apt-get install build-essential git pkg-config \
    libhackrf-dev libavutil-dev libavdevice-dev libavfilter-dev \
    libswresample-dev libswscale-dev libavformat-dev libavcodec-dev \
    libfreetype-dev libpng-dev zlib1g-dev
# optional
sudo apt-get install libsoapysdr-dev libosmo-fl2k-dev
```

On older releases the FreeType package is called `libfreetype6-dev`.

### Fedora (with RPM Fusion for FFmpeg)

```sh
sudo dnf install gcc make git pkgconf hackrf-devel ffmpeg-devel \
    freetype-devel libpng-devel zlib-devel
# optional
sudo dnf install SoapySDR-devel osmo-fl2k-devel
```

## Compiling

```sh
cd src
make -j4
```

The result is the `hacktv` binary in `src/`. Check it with:

```sh
./hacktv --version      # prints e.g. "hacktv 20261012-89af792"
./hacktv --list-modes
```

`make clean` removes the objects and the binary.

### Make variables

| Variable | Purpose |
|----------|---------|
| `EXTRA_CFLAGS` | Additional compiler flags, e.g. `EXTRA_CFLAGS="-mcpu=cortex-a72"` |
| `EXTRA_LDFLAGS` | Additional linker flags, e.g. `-static` |
| `EXTRA_PKGS` | Additional `pkg-config` packages to link |
| `CROSS_HOST` | Toolchain prefix for cross-compiling, e.g. `aarch64-linux-gnu-` |
| `PREFIX` | Root prepended to the install path (see below) |

## Installing

```sh
sudo make install
```

This only copies `hacktv` to `$(PREFIX)/usr/local/bin/`. With the default
empty `PREFIX` that is `/usr/local/bin/hacktv`. There is no uninstall target;
delete the file to remove it. The manual page is not installed automatically:

```sh
sudo install -m 644 hacktv.1 /usr/local/share/man/man1/
```

To run a HackRF or FL2K as a normal user, the udev rules shipped with the
`hackrf` and `osmo-fl2k` packages must be installed.

## Windows (cross-compiled on Linux)

Two scripts in `src/` build a static 64-bit Windows executable with MinGW-w64:

```sh
cd src
./build_win64.sh
```

`build_win64.sh` downloads and builds libusb, libhackrf, osmo-fl2k, fdk-aac,
Opus, FreeType, zlib, libpng, libiconv, zvbi, termiWin and FFmpeg into `src/build_win64/install_root`, then
builds `hacktv.exe` (without SoapySDR support). `build_win64_hacktv.sh` only rebuilds hacktv against an
existing dependency tree under `/build_win64/install_root`.

## Runtime files

All logos, test cards and fonts are compiled into the binary, so `hacktv` can
be copied on its own. The only external file it may look for is
`videocrypt10-data.bin` (a 64 MB signature table for the `sky10` and
`sky10ppv` Videocrypt modes), which is read from the current directory when a
signature is not in the built-in table. It is not part of this repository.
