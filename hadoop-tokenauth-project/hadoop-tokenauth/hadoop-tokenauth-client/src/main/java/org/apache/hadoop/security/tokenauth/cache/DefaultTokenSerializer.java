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

package org.apache.hadoop.security.tokenauth.cache;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.security.tokenauth.cache.kerberos.KeytabHandler;
import org.apache.hadoop.security.tokenauth.has.HASClient;

class DefaultTokenSerializer extends TokenSerializer {
  public static final Log LOG = LogFactory.getLog(DefaultTokenSerializer.class);

  private final String USERHOME;
  private final String TOKEN_FOLDER;
  private final String IDENTITY_TOKEN_FILE;

  {
    USERHOME = System.getProperty("user.home");
    TOKEN_FOLDER = USERHOME + File.separator + ".TokenAuth";
    IDENTITY_TOKEN_FILE = TOKEN_FOLDER + File.separator + "identitytoken";
  }

  private void ensureTokenFolder() throws IOException {
    File tokenFolder = new File(TOKEN_FOLDER);
    if (!tokenFolder.exists()) {
      if (!tokenFolder.mkdir()) throw new IOException();
    } else if (!tokenFolder.isDirectory()) {
      throw new IOException();
    }
  }

  @Override
  public void saveToken(byte[] token) throws IOException {
    ensureTokenFolder();
    FileOutputStream fileOutputStream = null;
    try {
      fileOutputStream = new FileOutputStream(IDENTITY_TOKEN_FILE);
      fileOutputStream.write(token, 0, token.length);
      LOG.info("IdentityToken is saved in " + IDENTITY_TOKEN_FILE);
    } catch (IOException e) {
      throw e;
    } finally {
      try {
        fileOutputStream.close();
      } catch (IOException e) {

      }
    }
  }

  @Override
  public byte[] readToken() throws IOException {
    ensureTokenFolder();
    File tokenFile = new File(IDENTITY_TOKEN_FILE);
    if (!tokenFile.exists() || !tokenFile.isFile()) {
      return null;
    }
    FileInputStream fileInputStream = null;
    try {
      fileInputStream = new FileInputStream(tokenFile);
      byte[] result = new byte[fileInputStream.available()];
      fileInputStream.read(result);
      return result;
    } catch (IOException e) {
      throw e;
    } finally {
      try {
        if (fileInputStream != null) {
          fileInputStream.close();
        }
      } catch (IOException e) {
      }
    }
  }

  public void saveAuthnFile(List<Callback> callbacks, String username,
      String authnPath, List<Callback> savedOnlyCallback,
      List<Class<? extends Callback>> readOnlyCallback) throws IOException {
    if (readOnlyCallback !=null)
      filterReadOnlyCallback(callbacks,readOnlyCallback);
    if (savedOnlyCallback != null)
      callbacks.addAll(savedOnlyCallback);
    Map<String, List<Callback>> authCallbacks = getAuthnFile(new File(authnPath));
    authCallbacks.put(username, callbacks);
    FileOutputStream fileOutputStream = null;
    ObjectOutputStream objOutputStream = null;
    try {
      fileOutputStream = new FileOutputStream(authnPath);
      objOutputStream = new ObjectOutputStream(fileOutputStream);
      objOutputStream.writeObject(authCallbacks);
      LOG.info("Authentication information of principal: " + username + " is saved in " + authnPath);
    } catch (IOException e) {
      throw e;
    } finally {
      try {
        if (fileOutputStream != null) {
          fileOutputStream.close();
        }
      } catch (Exception e) {
      }
    }
  }

  private void filterReadOnlyCallback(List<Callback> callbacks,
      List<Class<? extends Callback>> readOnlyCallback) {
    List<Callback> toRemoveCallbacks = new ArrayList<Callback>();
    for (Callback cb : callbacks) {
      if (readOnlyCallback.contains(cb.getClass())) {
        toRemoveCallbacks.add(cb);
      }
    }
    callbacks.removeAll(toRemoveCallbacks);
  }

  private List<Callback> readAuthnFile(String username,
      String authnFilePath) throws IOException {
    if (username == null || authnFilePath == null) {
      throw new NullPointerException("username and authnFilePath cannot be null");
    }
    File authnFile = new File(authnFilePath);
    if (!authnFile.exists() || !authnFile.isFile()) {
      return null;
    }
    return getAuthnFile(authnFile).get(username);
  }

  @SuppressWarnings("unchecked")
  private Map<String, List<Callback>> getAuthnFile(File authnFile) throws IOException {
    FileInputStream fileInputStream = null;
    ObjectInputStream objectInputStream = null;
    try {
      fileInputStream = new FileInputStream(authnFile);
      objectInputStream = new ObjectInputStream(fileInputStream);
      Map<String, List<Callback>> result =
          (Map<String, List<Callback>>) objectInputStream.readObject();
      return result;
    } catch (Exception e) {
      LOG.info("The file does not exist: "+authnFile);
    } finally {
      try {
        objectInputStream.close();
      } catch (Exception e) {

      }
    }
    return new LinkedHashMap<String, List<Callback>>();
  }

  public List<Callback> getCallbacks(HASClient hasClient, 
      String principal, String authnFilePath) throws IOException {
    List<Callback> callbacks = readAuthnFile(principal, authnFilePath);
    if(callbacks != null) {
      KeytabHandler krb5Handler = new KeytabHandler(hasClient);
      try {
        krb5Handler.handle(callbacks);
      } catch (UnsupportedCallbackException e) {
        LOG.error("UnsupportedCallback",e);
      }
      return callbacks;
    }
    return null;
  }
  
  public void cleanIdentityTokenFile() {
    File tokenFile = new File(IDENTITY_TOKEN_FILE);
    if (tokenFile != null && tokenFile.exists()) {
      tokenFile.delete();
    }
    File tokenFolder = new File(TOKEN_FOLDER);
    if (tokenFolder != null && tokenFolder.exists()) {
      tokenFolder.delete();
    }
    LOG.info("IdentityTokenFile is deleted");
  }
  
}
