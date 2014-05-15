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

package org.apache.hadoop.security.tokenauth.has;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.hadoop.HadoopIllegalArgumentException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.security.tokenauth.has.util.HASUtils;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;

public class GetConf extends Configured implements Tool {
  private static final String DESCRIPTION =
      "tokenauth getconf is utility for " + "getting configuration information from the config file.\n";

  enum Command {
    ISNODES("-isnodes", "gets list of identity server nodes in the cluster."),
    AUTHZNODES("-authznodes", "gets list of authorization server nodes in the cluster."),
    CONFKEY("-confKey [key]", "gets a specific key from the configuration");

    private static Map<String, CommandHandler> map;

    static {
      map = new HashMap<String, CommandHandler>();
      map.put(ISNODES.getName().toLowerCase(), new ISNodesCommandHandler());
      map.put(AUTHZNODES.getName().toLowerCase(), new AUTHZNodesCommandHandler());
      map.put(CONFKEY.getName().toLowerCase(), new PrintConfKeyCommandHandler());
    }

    private final String cmd;
    private final String description;

    Command(String cmd, String description) {
      this.cmd = cmd;
      this.description = description;
    }

    public String getName() {
      return cmd.split(" ")[0];
    }

    public String getUsage() {
      return cmd;
    }

    public String getDescription() {
      return description;
    }

    public static CommandHandler getHandler(String cmd) {
      return map.get(cmd.toLowerCase());
    }
  }

  static final String USAGE;

  static {
    /* Initialize USAGE based on Command values */
    StringBuilder usage = new StringBuilder(DESCRIPTION);
    usage.append("\nhadoop getconf \n");
    for (Command cmd : Command.values()) {
      usage.append("\t[" + cmd.getUsage() + "]\t\t\t" + cmd.getDescription() + "\n");
    }
    USAGE = usage.toString();
  }

  /**
   * Handler to return value for key corresponding to the {@link Command}
   */
  static class CommandHandler {
    String key; // Configuration key to lookup

    CommandHandler() {
      this(null);
    }

    CommandHandler(String key) {
      this.key = key;
    }

    final int doWork(GetConf tool, String[] args) {
      try {
        checkArgs(args);

        return doWorkInternal(tool, args);
      } catch (Exception e) {
        tool.printError(e.getMessage());
      }
      return -1;
    }

    protected void checkArgs(String args[]) {
      if (args.length > 0) {
        throw new HadoopIllegalArgumentException("Did not expect argument: " + args[0]);
      }
    }


    /**
     * Method to be overridden by sub classes for specific behavior
     *
     * @param args
     */
    int doWorkInternal(GetConf tool, String[] args) throws Exception {

      String value = tool.getConf().getTrimmed(key);
      if (value != null) {
        tool.printOut(value);
        return 0;
      }
      tool.printError("Configuration " + key + " is missing.");
      return -1;
    }
  }

  /**
   * Handler for {@link Command#ISNODES}
   */
  static class ISNodesCommandHandler extends CommandHandler {
    @Override
    int doWorkInternal(GetConf tool, String[] args) throws IOException {
      tool.printMap(HASUtils.getISServiceRpcAddresses(tool.getConf()));
      return 0;
    }
  }

  /**
   * Handler for {@link Command#ISNODES}
   */
  static class AUTHZNodesCommandHandler extends CommandHandler {
    @Override
    int doWorkInternal(GetConf tool, String[] args) throws IOException {
      tool.printMap(HASUtils.getAuthzServiceRpcAddresses(tool.getConf()));
      return 0;
    }
  }

  static class PrintConfKeyCommandHandler extends CommandHandler {
    @Override
    protected void checkArgs(String[] args) {
      if (args.length != 1) {
        throw new HadoopIllegalArgumentException("usage: " + Command.CONFKEY.getUsage());
      }
    }

    @Override
    int doWorkInternal(GetConf tool, String[] args) throws Exception {
      this.key = args[0];
      return super.doWorkInternal(tool, args);
    }
  }

  private final PrintStream out; // Stream for printing command output
  private final PrintStream err; // Stream for printing error

  GetConf(Configuration conf) {
    this(conf, System.out, System.err);
  }

  GetConf(Configuration conf, PrintStream out, PrintStream err) {
    super(conf);
    this.out = out;
    this.err = err;
  }

  void printError(String message) {
    err.println(message);
  }

  void printOut(String message) {
    out.println(message);
  }

  void printMap(InetSocketAddress address) {
    StringBuilder buffer = new StringBuilder();
    buffer.append(address.getHostName());

    printOut(buffer.toString());
  }

  private void printUsage() {
    printError(USAGE);
  }

  /**
   * Main method that runs the tool for given arguments.
   *
   * @param args arguments
   * @return return status of the command
   */
  private int doWork(String[] args) {
    if (args.length >= 1) {
      CommandHandler handler = Command.getHandler(args[0]);
      if (handler != null) {
        return handler.doWork(this, Arrays.copyOfRange(args, 1, args.length));
      }
    }
    printUsage();
    return -1;
  }

  @Override
  public int run(final String[] args) throws Exception {
    /* Identity server is authentication root and can be run directly. */
    return doWork(args);
  }

  public static void main(String[] args) throws Exception {
    if (HASUtils.parseHelpArgument(args, USAGE, System.out, true)) {
      System.exit(0);
    }

    int res = ToolRunner.run(new GetConf(new HASConfiguration()), args);
    System.exit(res);
  }
}
