#!/bin/sh

# if any line errors, stop script immediately
set -e

cd $HOME

# if the garrysmod_common dir doesn't exist (isn't cached yet), then git clone the repo
# otherwise, cd to it, pull the latest commit and updated all of its submodules
if [ ! -d "$HOME/garrysmod_common" ]; then
	git clone --recursive https://bitbucket.org/danielga/garrysmod_common.git
else
	cd garrysmod_common
	git pull
	git submodule update --init --recursive
	cd ..
fi

# if the sourcesdk dir doesn't exist (isn't cached yet), then wget the tar and extract it
if [ ! -d "$HOME/sourcesdk" ]; then
	wget https://bitbucket.org/danielga/garrysmod_common/downloads/sourcesdk.tar.bz2
	tar -jxvf sourcesdk.tar.bz2
fi

# if the premake-core dir doesn't exist (isn't cached yet), then wget the tar and extract it
# then cd to its dir, make, go back up and copy the executable to premake-core
if [ ! -d "$HOME/premake-core" ]; then
	wget https://bitbucket.org/danielga/garrysmod_common/downloads/premake-core.tar.bz2
	tar -jxvf premake-core.tar.bz2 -C premake-core-build
	cd premake-core-build
	make CC=gcc-5
	cd ..
	mkdir premake-core
	cp premake-core-build/premake-core/bin/release/premake5 premake-core
fi
