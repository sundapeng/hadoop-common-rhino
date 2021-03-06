#!/usr/bin/env bash

# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# Start hadoop identity server daemon.

usage="Usage: start-identityserver.sh"

bin=`dirname "${BASH_SOURCE-$0}"`
bin=`cd "$bin"; pwd`

DEFAULT_LIBEXEC_DIR="$bin"/../libexec
HADOOP_LIBEXEC_DIR=${HADOOP_LIBEXEC_DIR:-$DEFAULT_LIBEXEC_DIR}
. $HADOOP_LIBEXEC_DIR/hadoop-config.sh

#---------------------------------------------------------
# identity server

ISNODES=$($HADOOP_PREFIX/bin/has getconf -isnodes)

echo "Starting isnodes on [$ISNODES]"

"$HADOOP_PREFIX/sbin/hadoop-daemons.sh" \
  --config "$HADOOP_CONF_DIR" \
  --hostnames "$ISNODES" \
  --script "$HADOOP_PREFIX/bin/has" start identity-service

# eof
