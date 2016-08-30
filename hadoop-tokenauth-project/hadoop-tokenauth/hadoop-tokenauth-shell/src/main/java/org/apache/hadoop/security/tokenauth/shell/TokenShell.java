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
package org.apache.hadoop.security.tokenauth.shell;

import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;

public class TokenShell extends Configured implements Tool{

  protected CommandFactory commandFactory;
  private final String usagePrefix =
      "Usage: hadoop token [generic options]";

  // print all usages
  private void printUsage(PrintStream out) {
    printInfo(out, null, false);
  }

  private void printInstanceHelp(PrintStream out, Command instance) {
    boolean firstLine = true;
    for (String line : instance.getDescription().split("\n")) {
      String prefix;
      if (firstLine) {
        prefix = instance.getUsage() + ":\t";
        firstLine = false;
      } else {
        prefix = "\t\t";
      }
      System.out.println(prefix + line);
    }
  }

  private void printInfo(PrintStream out, String cmd, boolean showHelp) {
    if (cmd != null) {
      // display help or usage for one command
      Command instance = commandFactory.getInstance("-" + cmd);
      if (instance == null) {
        throw new NullPointerException(cmd);
      }
        printInstanceUsage(out, instance);
    } else {
      // display help or usage for all commands
      out.println(usagePrefix);

      // display list of short usages
      ArrayList<Command>
          instances = new ArrayList<Command>();
      for (String name : commandFactory.getNames()) {
        Command instance = commandFactory.getInstance(name);
          System.out.println("\t[" + instance.getUsage() + "]");
          instances.add(instance);
      }
      // display long descriptions for each command
      if (showHelp) {
        for (Command instance : instances) {
          out.println();
          printInstanceHelp(out, instance);
        }
      }
      out.println();
      ToolRunner.printGenericCommandUsage(out);
    }
  }

  private void printInstanceUsage(PrintStream out, Command instance) {
    out.println(usagePrefix + " " + instance.getUsage());
  }


  @Override
  public int run(String[] argv) throws Exception {
    init();

    int exitCode = -1;
    if (argv.length < 1) {
      printUsage(System.err);
    } else {
      String cmd = argv[0];
      Command instance = null;
      try {
        instance = commandFactory.getInstance(cmd);
        if (instance == null) {
          throw new NullPointerException();
        }
        exitCode = instance.run(Arrays.copyOfRange(argv, 1, argv.length));
      } catch (IllegalArgumentException e) {
        if (instance != null) {
          printInstanceUsage(System.err, instance);
        }
      } catch (Exception e) {
        e.printStackTrace(System.err);
      }
    }
    return exitCode;
  }

  protected void init() throws IOException {
    getConf().setQuietMode(true);
    if (commandFactory == null) {
      commandFactory = new CommandFactory(getConf());
      //commandFactory.addObject(new Help(), "-help");
      //commandFactory.addObject(new Usage(), "-usage");
      registerCommands(commandFactory);
    }
  }

  protected void registerCommands(CommandFactory factory) {
    factory.registerCommands(Command.class);
  }

  public static void main(String argv[]) throws Exception {
    TokenShell shell = new TokenShell();
    Configuration conf = new Configuration();
    //conf.setQuietMode(false);
    shell.setConf(conf);
    int res;
    try {
      res = ToolRunner.run(shell, argv);
    } finally {
    }
    System.exit(res);
  }
}
