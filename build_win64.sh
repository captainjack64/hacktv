#!/bin/bash

set -e
set -x

HOST=x86_64-w64-mingw32
PREFIX=$(pwd)/build_win64/install_root
export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig

mkdir -p $PREFIX
cd build_win64

# libusb
if [[ ! -f $PREFIX/lib/libusb-1.0.a ]]; then
	
	if [[ ! -f libusb-1.0.22.tar.bz2 ]]; then
		wget https://github.com/libusb/libusb/releases/download/v1.0.22/libusb-1.0.22.tar.bz2
		tar -xvjf libusb-1.0.22.tar.bz2
	fi
	
	cd libusb-1.0.22
	./configure --host=$HOST --prefix=$PREFIX --enable-static --disable-shared
	make -j4 install
	cd ..
fi

# hackrf
if [[ ! -f $PREFIX/lib/libhackrf.a ]]; then
	
	if [[ ! -f hackrf-2018.01.1.tar.gz ]]; then
		wget https://github.com/mossmann/hackrf/archive/v2018.01.1/hackrf-2018.01.1.tar.gz
		tar -xvzf hackrf-2018.01.1.tar.gz
	fi
	
	rm -rf hackrf-2018.01.1/host/libhackrf/build
	mkdir -p hackrf-2018.01.1/host/libhackrf/build
	cd hackrf-2018.01.1/host/libhackrf/build
	cmake .. \
		-DCMAKE_SYSTEM_NAME=Windows \
		-DCMAKE_C_COMPILER=$HOST-gcc \
		-DCMAKE_INSTALL_PREFIX=$PREFIX \
		-DCMAKE_INSTALL_LIBPREFIX=$PREFIX/lib \
		-DLIBUSB_INCLUDE_DIR=$PREFIX/include/libusb-1.0 \
		-DLIBUSB_LIBRARIES=$PREFIX/lib/libusb-1.0.a
	make -j4 install
	cd ../../../..
	mv $PREFIX/bin/*.a $PREFIX/lib/
	find $PREFIX -name libhackrf\*.dll\* -delete
fi

# osmo-fl2k
if [[ ! -f $PREFIX/lib/libosmo-fl2k.a ]]; then
	
	if [[ ! -d osmo-fl2k ]]; then
		git clone --depth 1 git://git.osmocom.org/osmo-fl2k
	fi
	
	rm -rf osmo-fl2k/build
	mkdir -p osmo-fl2k/build
	cd osmo-fl2k/build
	cmake .. \
		-DCMAKE_SYSTEM_NAME=Windows \
		-DCMAKE_C_COMPILER=$HOST-gcc \
		-DCMAKE_INSTALL_PREFIX=$PREFIX \
		-DCMAKE_INSTALL_LIBPREFIX=$PREFIX \
		-DCMAKE_INSTALL_LIBDIR=$PREFIX/lib \
		-DLIBUSB_INCLUDE_DIR=$PREFIX/include/libusb-1.0 \
		-DLIBUSB_LIBRARIES=$PREFIX/lib/libusb-1.0.a
	make -j4 install
	cd ../..
	mv $PREFIX/lib/liblibosmo-fl2k_static.a $PREFIX/lib/libosmo-fl2k.a
fi

# AAC codec
if [[ ! -f $PREFIX/lib/libfdk-aac.a ]]; then
	
	if [[ ! -d fdk-aac ]]; then
		git clone https://github.com/mstorsjo/fdk-aac.git
	fi
	
	cd fdk-aac
	./autogen.sh
	./configure --host=$HOST --prefix=$PREFIX --enable-static --disable-shared
	make -j4 install
	cd ..
fi

# opus codec
if [[ ! -f $PREFIX/lib/libopus.a ]]; then
	
	if [[ ! -f opus-1.3.1.tar.gz ]]; then
		wget https://archive.mozilla.org/pub/opus/opus-1.3.1.tar.gz
		tar -xvzf opus-1.3.1.tar.gz
	fi
	
	cd opus-1.3.1
	./configure CFLAGS='-D_FORTIFY_SOURCE=0' --host=$HOST --prefix=$PREFIX --enable-static --disable-shared --disable-doc --disable-extra-programs
	make -j4 install
	cd ..
fi

# zlib, required for logo support
if [[ ! -f $PREFIX/lib/libz.a ]]; then

    if [[ ! -f zlib-1.2.12.tar.gz ]]; then
        wget http://zlib.net/zlib-1.2.12.tar.gz
        tar xzvf zlib-1.2.12.tar.gz
    fi

    cd zlib-1.2.12
    CC=$HOST-gcc AR=$HOST-ar RANLIB=$HOST-ranlib \
    ./configure --prefix=$PREFIX --static
    make -j4 install
    cd ..
fi

# freetype2, required for subtitles and timestamp
if [[ ! -f $PREFIX/lib/libfreetype.a ]]; then

    if [[ ! -f freetype-2.10.4.tar.gz ]]; then
        wget https://download.savannah.gnu.org/releases/freetype/freetype-2.10.4.tar.gz
        tar xzvf freetype-2.10.4.tar.gz
    fi

    cd freetype-2.10.4
    ./configure --prefix=$PREFIX --disable-shared --with-pic --host=$HOST --without-zlib --with-png=no --with-harfbuzz=no
    make -j4 install
    cd ..
fi

# libpng, also required for logo support
if [[ ! -f $PREFIX/lib/libpng16.a ]]; then

    if [[ ! -f libpng-1.6.37.tar.gz ]]; then
        wget https://download.sourceforge.net/libpng/libpng-1.6.37.tar.gz
	    tar xzvf libpng-1.6.37.tar.gz
    fi

    cd libpng-1.6.37
    CPPFLAGS="-I$PREFIX/include" LDFLAGS="-L$PREFIX/lib" \
    ./configure --prefix=$PREFIX --host=$HOST
    make -j4 install
    cd ..
fi

# libiconv, pre-requisite for zvbi
if [[ ! -f $PREFIX/lib/libiconv.a ]]; then

    if [[ ! -f libiconv-1.16.tar.gz ]]; then
        wget https://ftp.gnu.org/pub/gnu/libiconv/libiconv-1.16.tar.gz
	    tar xzvf libiconv-1.16.tar.gz
    fi

    cd libiconv-1.16
    ./configure --prefix=$PREFIX --host=$HOST --enable-static --disable-shared
    make -j4 install
    cd ..
fi

# zvbi, required for handling teletext subtitles in transport streams
if [[ ! -f $PREFIX/lib/libzvbi.a ]]; then

    if [[ ! -f zvbi-0.2.35.tar.bz2 ]]; then
        wget https://download.sourceforge.net/project/zapping/zvbi/0.2.35/zvbi-0.2.35.tar.bz2
        tar xjvf zvbi-0.2.35.tar.bz2
        # Can't be cross compiled in its default state, needs to be patched first
        # This repo contains the patch files that we need
        git clone https://github.com/rdp/ffmpeg-windows-build-helpers.git
        cd zvbi-0.2.35
        patch -p0 < ../ffmpeg-windows-build-helpers/patches/zvbi-win32.patch
        patch < ../ffmpeg-windows-build-helpers/patches/zvbi-no-contrib.diff
    fi

    CPPFLAGS="-I$PREFIX/include" LDFLAGS="-L$PREFIX/lib" \
    ./configure \
        --prefix=$PREFIX --host=$HOST --enable-static --disable-shared --disable-dvb \
        --disable-bktr --disable-proxy --disable-nls --without-doxygen --without-libiconv-prefix 
    make -j4 install
    cd ..
fi

# ffmpeg
if [[ ! -f $PREFIX/lib/libavformat.a ]]; then
	
	if [[ ! -d ffmpeg ]]; then
		git clone --depth 1 https://github.com/FFmpeg/FFmpeg.git ffmpeg
	fi
	
	cd ffmpeg
	./configure \
		--enable-gpl --enable-nonfree --enable-libfdk-aac --enable-libopus \
		--enable-static --disable-shared --disable-programs --enable-zlib \
		--enable-libfreetype --enable-libzvbi --disable-outdevs --disable-encoders \
		--arch=x86_64 --target-os=mingw64 --cross-prefix=$HOST- \
		--pkg-config=pkg-config --prefix=$PREFIX
	make -j4 install
	cd ..
fi

cd ..
CROSS_HOST=$HOST- make -j4 EXTRA_LDFLAGS="-static" EXTRA_PKGS="libusb-1.0"
mv -f hacktv hacktv.exe || true
$HOST-strip hacktv.exe

echo "Done"