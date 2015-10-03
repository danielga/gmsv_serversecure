#!/bin/sh

if [[ ${TRAVIS_OS_NAME} = osx ]] && [[ ${CC} = gcc ]]; then
	export CXX=g++-4.8
	export CC=gcc-4.8
elif [[ ${TRAVIS_OS_NAME} = linux ]]; then
	export CXX=g++-5
	export CC=gcc-5
fi

# if any line errors, stop script immediately
set -e

cd $HOME

# if the garrysmod_common dir doesn't exist (isn't cached yet), then git clone the repo
# otherwise, cd to it, pull the latest commit and updated all of its submodules
if [ ! -d "$HOME/garrysmod_common" ]; then
	echo "garrysmod_common directory doesn't exist, doing git clone of the remote repo"
	git clone --recursive https://bitbucket.org/danielga/garrysmod_common.git
else
	echo "garrysmod_common directory exists, pulling any latest changes"
	cd garrysmod_common
	git pull
	git submodule update --init --recursive
	cd ..
fi

# if the sourcesdk dir doesn't exist (isn't cached yet), then wget the tar and extract it
if [ ! -d "$HOME/sourcesdk" ]; then
	echo "sourcesdk directory doesn't exist, doing wget and untar"
	wget https://bitbucket.org/danielga/garrysmod_common/downloads/sourcesdk.tar.bz2
	tar -jxvf sourcesdk.tar.bz2
fi

# if the premake-core dir doesn't exist (isn't cached yet), then wget the tar and extract it
# then cd to its dir, make, go back up and copy the executable to premake-core
if [ ! -d "$HOME/premake-core" ]; then
	echo "premake-core directory doesn't exist, doing wget, untar, make and copy"
	wget https://bitbucket.org/danielga/garrysmod_common/downloads/premake-core.tar.bz2
	tar -jxvf premake-core.tar.bz2
	mv premake-core premake-core-build
	cd premake-core-build
	make
	cd ..
	mkdir premake-core
	cp premake-core-build/premake-core/bin/release/premake5 premake-core
fi
