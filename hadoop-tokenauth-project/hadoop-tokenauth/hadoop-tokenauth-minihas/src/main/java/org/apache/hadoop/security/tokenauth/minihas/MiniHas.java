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
package org.apache.hadoop.security.tokenauth.minihas;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.cache.TokenSerializer;
import org.apache.hadoop.security.tokenauth.has.HASClient;
import org.apache.hadoop.security.tokenauth.has.HASClientImpl;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.apache.hadoop.security.tokenauth.has.authorization.AuthorizationService;
import org.apache.hadoop.security.tokenauth.has.identity.IdentityService;
import org.apache.hadoop.security.tokenauth.kerberos.KerberosCallback;
import org.apache.hadoop.security.tokenauth.shell.kerberos.Krb5ShellHandler;
import org.apache.hadoop.security.tokenauth.shell.kerberos.Krb5UseKeytabHandler;

/**
 * This class creates a single-process tokenauth services for junit testing. The data directories
 * for tokenauth are under the temp directory $MINI_TOKENAUTH_BASEDIR. Two thread to start identity
 * service and authorization service.
 */
public class MiniHas {

  private Map<String, String> propMap = new HashMap<String, String>();
  private IdentityService is;
  private AuthorizationService as;
  private File base_dir;
  private boolean isFailed = false;
  private boolean asFailed = false;

  private static final String MINI_TOKENAUTH_BASEDIR = "test.tokeauth.basedir";
  private static final String AUTHO_POLICY_SCRIPT_FILE_NAME = MINI_TOKENAUTH_BASEDIR
      + "/authorization-policy-script";
  private static final String AUTHO_POLICY_SCRIPT_FILE = "function evaluate(){return true;}";
  private static final String PRINCIPAL = "root";
  private static final String AUTHN_FILE = MINI_TOKENAUTH_BASEDIR + "/root.sso";
  private static final String IDENTITY_TOKEN_PERSISTENT_ON_EXIT = "hadoop.security.tokenauth.identity.server.issuedtokens.persistent.on.exit";
  private static final String IDENTITY_TOKEN_PERSISTENT_FILE_KEY = "hadoop.security.tokenauth.identity.server.issuedtokens.persistent.file";
  private static final String IDENTITYTOKEN_PERSISTENT_FILE = MINI_TOKENAUTH_BASEDIR
      + "/identity-token-persistent";
  private static final String HADOOP_SECURITY_AUTHENTICATION = "hadoop.security.authentication";
  private static final String HADOOP_SECURITY_AUTHORIZATION = "hadoop.security.authorization";
  private static final String ACCESS_TOKEN_ENABLE = "dfs.block.access.token.enable";
  private static final String IDENTITY_HTTP_ADDR = "hadoop.security.identity.server.http-address";
  private static final String AUTHORIZATION_HTTP_ADDR = "hadoop.security.authorization.server.http-address";
  private static final String IDENTITY_RPC_ADDR = "hadoop.security.identity.server.rpc-address";
  private static final String AUTHORIZATION_RPC_ADDR = "hadoop.security.authorization.server.rpc-address";
  private static final String HADOOP_SECURITY_TOKENAUTH_AUTHENTICATORS_KEY_DEFAULT = "simple";
  private static final String HADOOP_SECURITY_TOKENAUTH_AUTHENTICATOR_CONTROLFLAG_DEFAULT = "required";
  private static final String HADOOP_SECURITY_AUTHENTICATION_DEFAULT = "tokenauth";
  private static final String IDENTITY_HTTP_ADDR_DEFAULT = "localhost:8786";
  private static final String AUTHORIZATION_HTTP_ADDR_DEFAULT = "localhost:8787";
  private static final String IDENTITY_RPC_ADDR_DEFAULT = "localhost:8781";
  private static final String AUTHORIZATION_RPC_ADDR_DEFAULT = "localhost:8782";
  private static final Log LOG = LogFactory.getLog(MiniHas.class);

  /**
   * Class to construct instances of MiniHas with specific options.
   */
  public static class Builder {

    private Map<String, String> propMap = new HashMap<String, String>();

    public Builder(Map<String, String> map) {
      propMap = map;
    }

    public Builder() {
      // has configuration
      propMap.put(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATORS_KEY,
          HADOOP_SECURITY_TOKENAUTH_AUTHENTICATORS_KEY_DEFAULT);
      propMap.put(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATOR_PREFIX
          + HADOOP_SECURITY_TOKENAUTH_AUTHENTICATORS_KEY_DEFAULT
          + HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATOR_CONTROLFLAG,
          HADOOP_SECURITY_TOKENAUTH_AUTHENTICATOR_CONTROLFLAG_DEFAULT);
      propMap.put(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_PRINCIPAL_KEY,
          PRINCIPAL);
      propMap.put(
          HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_AUTHENTICATION_FILE_KEY,
          AUTHN_FILE);
      propMap.put(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_ENGINE_IMPL,
          HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_ENGINE_IMPL_MINI);
      propMap.put(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_POLICY,
          AUTHO_POLICY_SCRIPT_FILE_NAME);
      propMap.put(IDENTITY_TOKEN_PERSISTENT_FILE_KEY, IDENTITYTOKEN_PERSISTENT_FILE);
      propMap.put(IDENTITY_TOKEN_PERSISTENT_ON_EXIT, "false");
      propMap.put(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_ADMIN_KEY, "root");

      // hadoop-core configuration
      propMap.put(HADOOP_SECURITY_AUTHENTICATION, HADOOP_SECURITY_AUTHENTICATION_DEFAULT);
      propMap.put(HADOOP_SECURITY_AUTHORIZATION, "true");
      propMap.put(ACCESS_TOKEN_ENABLE, "true");
      propMap.put(IDENTITY_HTTP_ADDR, IDENTITY_HTTP_ADDR_DEFAULT);
      propMap.put(AUTHORIZATION_HTTP_ADDR, AUTHORIZATION_HTTP_ADDR_DEFAULT);
      propMap.put(IDENTITY_RPC_ADDR, IDENTITY_RPC_ADDR_DEFAULT);
      propMap.put(AUTHORIZATION_RPC_ADDR, AUTHORIZATION_RPC_ADDR_DEFAULT);
    }

    /**
     * Default: simple
     */
    public Builder SetAuthenticatorsKeys(String val) {
      propMap.put(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATORS_KEY, val);
      return this;
    }

    /**
     * Default: required
     */
    public Builder setAuthenticatorControlFlag(String val) {
      propMap.put(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATOR_PREFIX + "simple"
          + HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATOR_CONTROLFLAG, val);
      return this;
    }

    /**
     * Default: root
     */
    public Builder setAuthoPrincipalKey(String val) {
      propMap.put(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_PRINCIPAL_KEY,
          val);
      return this;
    }

    /**
     * Default: $BASE_DIR_NAME/root.sso
     */
    public Builder setAuthenFile(String val) {
      propMap.put(
          HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_AUTHENTICATION_FILE_KEY,
          val);
      return this;
    }

    /**
     * Default: localhost:8776
     */
    public Builder setIdentityHttpAddr(String addr) {
      propMap.put(IDENTITY_HTTP_ADDR, addr);
      return this;
    }

    /**
     * Default: localhost:8777
     */
    public Builder setAuthoHttpAddr(String addr) {
      propMap.put(AUTHORIZATION_HTTP_ADDR, addr);
      return this;
    }

    /**
     * Default: localhost:8771
     */
    public Builder setIdentityRpcAddr(String addr) {
      propMap.put(IDENTITY_RPC_ADDR, addr);
      return this;
    }

    /**
     * Default: localhost:8772
     */
    public Builder setAuthoRpcAddr(String addr) {
      propMap.put(AUTHORIZATION_RPC_ADDR, addr);
      return this;
    }

    /**
     * Default: tokenauth
     */
    public Builder setAuthentication(String val) {
      propMap.put(HADOOP_SECURITY_AUTHENTICATION, val);
      return this;
    }

    /**
     * Default: true
     */
    public Builder setAuthorization(String val) {
      propMap.put(HADOOP_SECURITY_AUTHORIZATION, val);
      return this;
    }

    /**
     * Default: true
     */
    public Builder setAccessTokenEnable(String val) {
      propMap.put(ACCESS_TOKEN_ENABLE, val);
      return this;
    }

    /**
     * Default: root
     */
    public Builder setIdentityAdmin(String val) {
      propMap.put(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_ADMIN_KEY, val);
      return this;
    }
    
    /**
     * Other Property
     */
    public Builder setOtherProperty(String key, String val) {
      propMap.put(key, val);
      return this;
    }

    /**
     * Construct the actual MiniHas
     */
    public MiniHas build() throws Exception {
      return new MiniHas(this);
    }
  }

  /**
   * Class to start identity service.
   */
  class MiniIdentityThread implements Runnable {

    @Override
    public void run() {
      is = IdentityService.create(propMap);
      try {
        is.run(null);
      } catch (Exception e) {
        if (is != null) {
          isFailed = true;
          is.stop();
        }
      }
    }
  }

  /**
   * Class to start authorization service.
   */
  class MiniAuthThread implements Runnable {

    @Override
    public void run() {
      as = AuthorizationService.create(propMap);
      try {
        as.run(null);
      } catch (Exception e) {
        if (as != null) {
          asFailed = true;
          as.stop();
        }
      }
    }
  }

  protected MiniHas(Builder builder) throws Exception {
    this.propMap = builder.propMap;
    initMiniHas();
  }

  private synchronized void initMiniHas() throws Exception {
    // 1. start identity service
    MiniIdentityThread it = new MiniIdentityThread();
    MiniAuthThread at = new MiniAuthThread();
    Thread t1 = new Thread(it);
    t1.start();

    // 2. wait for indentity service started
    int i = 0;
    while (!isIdentityServiceUp()) {
      try {
        LOG.warn("Waiting for the Identity Service to start...");
        Thread.sleep(1000);
      } catch (InterruptedException e) {
      }
      if (++i > 30) {
        throwError("Timed out waiting for Identity Service to start.");
      } else if (isFailed == true) {
        throwError("Identity service start failed.");
      }
    }

    if (!isIdentityServiceUp()) {
      return;
    }

    LOG.info("Identity Service started.");

    // 3. build temp dir and files
    buildTmpFiles();

    // 4. start authorization service
    Thread t2 = new Thread(at);
    t2.start();
  }

  private void buildTmpFiles() throws IOException {
    base_dir = new File(MINI_TOKENAUTH_BASEDIR);
    base_dir.mkdir();

    // 1. build authorization-policy-script
    File policyScriptFile = new File(AUTHO_POLICY_SCRIPT_FILE_NAME);
    FileOutputStream fout = new FileOutputStream(policyScriptFile);
    fout.write(AUTHO_POLICY_SCRIPT_FILE.getBytes());
    fout.close();

    // 2. build auth file
    String identityHttpAddr = propMap.get(IDENTITY_HTTP_ADDR);
    HASClient client = new HASClientImpl("http://" + identityHttpAddr, null);
    IdentityRequest request = new IdentityRequest(null, null);
    IdentityResponse response = client.authenticate(request);

    List<Callback> callbacks = new LinkedList<Callback>();
    for (Callback cb : response.getRequiredCallbacks()) {
      if (cb instanceof NameCallback) {
        ((NameCallback) cb).setName(PRINCIPAL);
        callbacks.add(cb);
      }
    }

    final List<Class<? extends Callback>> readOnlyCallbacks;
    readOnlyCallbacks = new ArrayList<Class<? extends Callback>>();
    readOnlyCallbacks.add(KerberosCallback.class);

    final Krb5ShellHandler handler = new Krb5UseKeytabHandler(null);
    String username = PRINCIPAL;
    String authnPath = AUTHN_FILE;
    TokenSerializer.get().saveAuthnFile(callbacks, username, authnPath,
        handler.getSavedOnlyCallback(), readOnlyCallbacks);
  }

  public void shutdown() {
    shutdown(false);
  }

  /**
   * Shutdown all the services in the has.
   */
  public synchronized void shutdown(boolean isDelete) {
    shutdownServices();

    LOG.info("Mini HAS stopped.");

    if (base_dir != null) {
      if (isDelete) {
        deleteFile(base_dir);
      } else {
        deleteFileOnExit(base_dir);
      }
    }
  }

  private void deleteFile(File file) {
    if (file.exists()) {
      if (file.isFile()) {
        file.delete();
      } else if (file.isDirectory()) {
        File files[] = file.listFiles();
        for (File f : files) {
          deleteFile(f);
        }
      }
      file.delete();
    } else {
      LOG.warn("Can't delete this file because this file don't exists.");
    }
  }

  private void deleteFileOnExit(File file) {
    if (file.exists()) {
      file.deleteOnExit();
      if (file.isFile()) {
        file.deleteOnExit();
      } else if (file.isDirectory()) {
        File files[] = file.listFiles();
        for (File f : files) {
          deleteFileOnExit(f);
        }
      }
    } else {
      LOG.warn("Can't delete this file because this file don't exists.");
    }
  }

  private void shutdownServices() {
    if (is != null) {
      is.stop();
    }

    if (as != null) {
      as.stop();
    }
  }

  private boolean isIdentityServiceUp() {
    return is != null && is.isAlive();
  }

  private boolean isAuthorizationServiceUp() {
    return as != null && as.isAlive();
  }

  private boolean isHasUp() {
    return isIdentityServiceUp() && isAuthorizationServiceUp();
  }

  private void throwError(String message) throws IOException {
    LOG.error(message);
    shutdown(true);
    throw new IOException(message);
  }

  /**
   * wait for the all services to started
   */
  public void waitHasUp() throws IOException, InterruptedException {
    int i = 0;
    while (!isHasUp()) {
      try {
        LOG.warn("Waiting for the Mini Has to start...");
        Thread.sleep(1000);
      } catch (InterruptedException e) {
      }
      if (++i > 30) {
        throwError("Timed out waiting for Mini Has to start.");
      } else if (isFailed == true) {
        throwError("Identity service start failed.");
      } else if (asFailed == true) {
        throwError("Authorization service start failed.");
      }
    }
    if (i < 30) {
      LOG.info("Authorization Service started.");
      LOG.info("Min Has started.");
    }
  }
}
