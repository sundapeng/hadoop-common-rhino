/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.security.tokenauth.has.util;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.util.ToolRunner;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

public class HASUtils {

  public static InetSocketAddress getISServiceRpcAddresses(
      Configuration conf) throws IOException {
    String addr = conf.get(CommonConfigurationKeysPublic.HADOOP_SECURITY_IDENTITY_SERVER_RPC_ADDRESS_KEY
        , CommonConfigurationKeysPublic.HADOOP_SECURITY_IDENTITY_SERVER_RPC_ADDRESS_DEFAULT);
    return NetUtils.createSocketAddr(addr, 0, CommonConfigurationKeysPublic.HADOOP_SECURITY_IDENTITY_SERVER_RPC_ADDRESS_KEY);
  }

  public static InetSocketAddress getAuthzServiceRpcAddresses(
      Configuration conf) throws IOException {
    String addr = conf.get(CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_RPC_ADDRESS_KEY
        , CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_RPC_ADDRESS_DEFAULT);
    return NetUtils.createSocketAddr(addr, 0, CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_RPC_ADDRESS_KEY);
  }

  public static Options helpOptions = new Options();
  public static Option helpOpt = new Option("h", "help", false, "get help information");

  static {
    helpOptions.addOption(helpOpt);
  }

  /**
   * Parse the arguments for commands
   *
   * @param args                     the argument to be parsed
   * @param helpDescription          help information to be printed out
   * @param out                      Printer
   * @param printGenericCommandUsage whether to print the generic command usage defined in ToolRunner
   * @return true when the argument matches help option, false if not
   */
  public static boolean parseHelpArgument(String[] args, 
      String helpDescription, PrintStream out, boolean printGenericCommandUsage) {
    if (args.length == 1) {
      try {
        CommandLineParser parser = new PosixParser();
        CommandLine cmdLine = parser.parse(helpOptions, args);
        if (cmdLine.hasOption(helpOpt.getOpt()) || cmdLine.hasOption(helpOpt.getLongOpt())) {
          // should print out the help information
          out.println(helpDescription + "\n");
          if (printGenericCommandUsage) {
            ToolRunner.printGenericCommandUsage(out);
          }
          return true;
        }
      } catch (ParseException pe) {
        return false;
      }
    }
    return false;
  }

  public static String getUserNameFromKerberos(String username) {

    if (username.contains("@")){
      int firstPos = username.indexOf("@");
      if (firstPos == username.lastIndexOf("@")) {
        username = username.substring(0,firstPos);
      } else {
        throw new IllegalArgumentException();
      }
    }
    return username;
  }
}

