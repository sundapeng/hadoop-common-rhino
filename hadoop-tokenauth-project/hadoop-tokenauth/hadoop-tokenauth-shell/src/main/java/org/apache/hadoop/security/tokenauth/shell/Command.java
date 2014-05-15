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
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import javax.security.auth.login.LoginException;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.util.StringUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * An abstract class for the execution of a tokenAuth command
 */
@InterfaceAudience.Private
@InterfaceStability.Evolving
abstract public class Command extends Configured {

  public static void registerCommands(CommandFactory factory) {
    factory.registerCommands(TokenCommand.class);
  }

  /** field name indicating the default name of the command */
  public static final String COMMAND_NAME_FIELD = "NAME";
  /** field name indicating the command's usage switches and arguments format */
  public static final String COMMAND_USAGE_FIELD = "USAGE";
  /** field name indicating the command's long description */
  public static final String COMMAND_DESCRIPTION_FIELD = "DESCRIPTION";
    
  protected String[] args;
  protected String name;
  protected int exitCode = 0;
  protected int numErrors = 0;
  protected ArrayList<Exception> exceptions = new ArrayList<Exception>();

  private static final Log LOG = LogFactory.getLog(Command.class);

  /** allows stdout to be captured if necessary */
  public PrintStream out = System.out;
  /** allows stderr to be captured if necessary */
  public PrintStream err = System.err;

  /** Constructor */
  protected Command() {
    out = System.out;
    err = System.err;
  }
  
  /** Constructor */
  protected Command(Configuration conf) {
    super(conf);
  }
  
  /** @return the command's name excluding the leading character - */
  abstract public String getCommandName();
  

  /**
   * Invokes the command handler.  The default behavior is to process options,
   * expand arguments, and then process each argument.
   * <pre>
   * run
   * |-> {@link #processArguments(java.util.LinkedList)}
   * </pre>
   * Most commands will chose to implement just
   * {@link #processArguments(java.util.LinkedList)}}
   *
   * @param argv the list of command line arguments
   * @return the exit code for the command
   * @throws IllegalArgumentException if called with invalid arguments
   */
  public int run(String...argv) throws LoginException {
    LinkedList<String> args = new LinkedList<String>(Arrays.asList(argv));
    try {
      processArguments(args);
    } catch (IOException e) {
      displayError(e);
    }

    return (numErrors == 0) ? exitCode : exitCodeForError();
  }


  /**
   * The exit code to be returned if any errors occur during execution.
   * This method is needed to account for the inconsistency in the exit
   * codes returned by various commands.
   * @return a non-zero exit code
   */
  protected int exitCodeForError() { return 1; }

  /**
   * Must be implemented by commands to process the command line flags and
   * check the bounds of the remaining arguments.  If an
   * IllegalArgumentException is thrown, the FsShell object will print the
   * short usage of the command.
   * @param args the command line arguments
   * @throws java.io.IOException
   */
  protected void processArguments(LinkedList<String> args) throws IOException,
      LoginException {}

  /**
   * Display an exception prefaced with the command name.  Also increments
   * the error count for the command which will result in a non-zero exit
   * code.
   * @param e exception to display
   */
  public void displayError(Exception e) {
    // build up a list of exceptions that occurred
    exceptions.add(e);

    String errorMessage = e.getLocalizedMessage();
    if (errorMessage == null) {
      // this is an unexpected condition, so dump the whole exception since
      // it's probably a nasty internal error where the backtrace would be
      // useful
      errorMessage = StringUtils.stringifyException(e);
      LOG.debug(errorMessage);
    } else {
      errorMessage = errorMessage.split("\n", 2)[0];
    }
    displayError(errorMessage);
  }
  
  /**
   * Display an error string prefaced with the command name.  Also increments
   * the error count for the command which will result in a non-zero exit
   * code.
   * @param message error message to display
   */
  public void displayError(String message) {
    numErrors++;
    displayWarning(message);
  }
  
  /**
   * Display an warning string prefaced with the command name.
   * @param message warning message to display
   */
  public void displayWarning(String message) {
    err.println(getName() + ": " + message);
  }
  
  /**
   * The name of the command.  Will first try to use the assigned name
   * else fallback to the command's preferred name
   * @return name of the command
   */
  public String getName() {
    return (name == null)
      ? getCommandField(COMMAND_NAME_FIELD)
      : name.startsWith("-") ? name.substring(1) : name;
  }

  /**
   * Define the name of the command.
   * @param name as invoked
   */
  public void setName(String name) {
    this.name = name;
  }
  
  /**
   * The short usage suitable for the synopsis
   * @return "name options"
   */
  public String getUsage() {
    String cmd = "-" + getName();
    String usage = getCommandField(COMMAND_USAGE_FIELD);
    return usage.isEmpty() ? cmd : cmd + " " + usage; 
  }

  /**
   * The long usage suitable for help output
   * @return text of the usage
   */
  public String getDescription() {
    return getCommandField(COMMAND_DESCRIPTION_FIELD);
  }

  /**
   * Get a public static class field
   * @param field the field to retrieve
   * @return String of the field
   */
  private String getCommandField(String field) {
    String value;
    try {
      Field f = this.getClass().getDeclaredField(field);
      f.setAccessible(true);
      value = f.get(this).toString();
    } catch (Exception e) {
      throw new RuntimeException(
          "failed to get " + this.getClass().getSimpleName()+"."+field, e);
    }
    return value;
  }
  
}
