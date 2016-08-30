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

import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;

public class ShellCallbackHandler extends Configured implements CallbackHandler{

  public ShellCallbackHandler(Configuration conf){
    setConf(conf);
  }

  protected static String readPwd(String pref) throws IOException {
    pref = pref + ": ";
    Console c = System.console();
    if (c == null) { //IN ECLIPSE IDE
      System.out.print(pref);
      InputStream in = System.in;
      int max = 50;
      byte[] b = new byte[max];

      int l = in.read(b);
      l--;//last character is \n
      if (l > 0) {
        byte[] e = new byte[l];
        System.arraycopy(b, 0, e, 0, l);
        return new String(e);
      } else {
        return null;
      }
    } else { //Outside Eclipse IDE
      return new String(c.readPassword(pref));
    }
  }

  protected static String readName(String pref) throws IOException {
    pref = pref + ": ";
    Console c = System.console();
    if (c == null) { //IN ECLIPSE IDE
      System.out.print(pref);
      InputStream in = System.in;
      int max = 50;
      byte[] b = new byte[max];

      int l = in.read(b);
      l--;//last character is \n
      if (l > 0) {
        byte[] e = new byte[l];
        System.arraycopy(b, 0, e, 0, l);
        return new String(e);
      } else {
        return null;
      }
    } else { //Outside Eclipse IDE
      return new String(c.readLine(pref));
    }
  }

  @Override
  public void handle(Callback[] callbacks) throws IOException,
      UnsupportedCallbackException {
    if (callbacks != null) {
      for (Callback cb : callbacks) {
        handle(cb);
      }
    }
  }

  protected static void handle(Callback cb) throws IOException,
      UnsupportedCallbackException {
    if (cb instanceof NameCallback) {
      NameCallback nameCallback = (NameCallback) cb;
      nameCallback.setName(readName(nameCallback.getPrompt()));
    } else if (cb instanceof PasswordCallback) {
      PasswordCallback passwordCallback = (PasswordCallback) cb;
      passwordCallback
          .setPassword(readPwd(passwordCallback.getPrompt()).toCharArray());
    } else if (cb instanceof TextInputCallback) {
      TextInputCallback textInputCallback = (TextInputCallback) cb;
      textInputCallback.setText(readName(textInputCallback.getPrompt()));
    } else if (cb instanceof TextOutputCallback) {
      TextOutputCallback textOutputCallback = (TextOutputCallback) cb;
      System.out.println(textOutputCallback.getMessage());
    } else if (cb instanceof RealmCallback){
      RealmCallback realmCallback = (RealmCallback)cb;
      realmCallback.setText(readName(realmCallback.getPrompt()));
    } else {
      throw new UnsupportedCallbackException(cb);
    }
  }


}
