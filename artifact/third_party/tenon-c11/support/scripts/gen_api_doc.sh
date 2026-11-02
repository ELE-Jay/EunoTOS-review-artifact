#!/usr/bin/env bash
#
# Copyright <year> Hangzhou Yingyi Technology Co., Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
# use rules
################################################################################
# execute this script followed by the directory of the files
# e.g. bash gen_api_doc.sh /home/user/unikaft/lib/uktest

# read input args
# directorys where files are indexed and read to generate docs
inputdir=$1
outputdir=$2

# initializing build environment

pwd=$(/usr/bin/pwd)
workspace=$pwd/workspace-$(date +%s)
mkdir -p $workspace

_SELF=$( readlink -f "$0" )
BASE=$( dirname "${_SELF}" )

# workspace is a temporary folder to store modified config files
workspace=$BASE/workspace-$(date +%s)
mkdir -p $workspace


pushd $workspace

function isCmdExist() {
	local cmd="$1"

	which "$cmd" >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		return 0
	fi

	return -1
}

# precheck
# check if doxygen exists
isCmdExist doxygen
ret=$?
if [ "$ret" -ne "0" ]; then
    apt-get install doxygen
    echo "doxygen installed"
else
    echo "doxygen exists"
fi

# check if directories exists
if [ ! -d $inputdir ];then
    echo "input directory does not exist"
    return -1
fi
if [ ! -d $outputdir ];then
    echo "input directory does not exist"
    return -1
fi

# generate doxygen config file
cp $BASE/gen_api_doc_config.template $workspace/gen_api_doc_config
sed -i "s|{{INPUT_DIR}}|$inputdir|g" $workspace/gen_api_doc_config
sed -i "s|{{OUTPUT_DIR}}|$outputdir|g" $workspace/gen_api_doc_config

# generate docs
doxygen $workspace/gen_api_doc_config

# clean workspace
rm -rf $workspace
