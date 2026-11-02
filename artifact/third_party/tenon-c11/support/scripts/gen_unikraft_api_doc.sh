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

SHELL_FOLDER=$(cd "$(dirname "$0")";pwd)
UK_ROOT=$( dirname "${SHELL_FOLDER}/../../../" )
pushd $UK_ROOT

#generate outputdir to store api docs
mkdir -p doc/api
outputdir=$UK_ROOT/doc/api
inputdir=$UK_ROOT

bash -e $SHELL_FOLDER/gen_api_doc.sh $inputdir $outputdir
