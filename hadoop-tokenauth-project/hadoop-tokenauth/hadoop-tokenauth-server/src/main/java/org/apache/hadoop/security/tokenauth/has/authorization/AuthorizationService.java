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

package org.apache.hadoop.security.tokenauth.has.authorization;


import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.PrivilegedAction;
import java.util.Map;

import javax.net.SocketFactory;

import org.apache.hadoop.HadoopIllegalArgumentException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.tokenauth.authorize.policy.EvaluationContext;
import org.apache.hadoop.security.tokenauth.authorize.policy.PolicyEngine;
import org.apache.hadoop.security.tokenauth.authorize.policy.PolicyEngineFactory;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.apache.hadoop.security.tokenauth.has.HASPolicyProvider;
import org.apache.hadoop.security.tokenauth.has.authorization.http.AuthorizationHttpServer;
import org.apache.hadoop.security.tokenauth.has.authorization.rpc.AuthorizationRPCServer;
import org.apache.hadoop.security.tokenauth.has.protocol.SecretsProtocol;
import org.apache.hadoop.security.tokenauth.has.protocolPB.SecretsProtocolClientSideTranslatorPB;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;
import org.apache.hadoop.security.tokenauth.token.impl.AccessToken;
import org.apache.hadoop.util.GenericOptionsParser;
import org.apache.hadoop.util.Time;

public class AuthorizationService {
  private Configuration conf;
  private SecretsProtocol secretsProtocol;
  protected AuthorizationHttpServer httpServer;
  protected AuthorizationRPCServer rpcServer;
  private final TokenFactory tokenFactory;
  private final PolicyEngine policyEngine;

  private AuthorizationService(Configuration conf) {
    this.conf = conf;
    tokenFactory = TokenFactory.get();
    String engineName = conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_ENGINE_IMPL, 
        HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_ENGINE_IMPL_DEFAULT);
    String policy = conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_POLICY, 
        HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_POLICY_DEFAULT);
    try {
      policyEngine = PolicyEngineFactory.createPolicyEngine(engineName, policy);
    } catch (ClassNotFoundException e) {
      throw new RuntimeException("Can't init policy engine");
    }
  }
  
  public static AuthorizationService create(Configuration conf) {
    return new AuthorizationService(conf);
  }
  
  public static AuthorizationService create(Map<String, String> propMap) {
    Configuration conf = new HASConfiguration();
    for (Map.Entry<String, String> mapEntry : propMap.entrySet()) {
      if (mapEntry.getValue().equalsIgnoreCase("true")) {
        conf.setBoolean(mapEntry.getKey(), true);
      } else if (mapEntry.getValue().equalsIgnoreCase("false")) {
        conf.setBoolean(mapEntry.getKey(), false);
      } else {
        conf.set(mapEntry.getKey(), mapEntry.getValue());
      }
    }
    UserGroupInformation.setConfiguration(conf);
    return new AuthorizationService(conf);
  }
  
  private void ensureConnectIdentityServer() throws IOException {
    if(secretsProtocol == null) {
      synchronized(this) {
        if(secretsProtocol == null) {
          SocketFactory factory = NetUtils.getDefaultSocketFactory(conf);
          InetSocketAddress address = NetUtils.createSocketAddr(
              conf.get(CommonConfigurationKeys.HADOOP_SECURITY_IDENTITY_SERVER_RPC_ADDRESS_KEY), 0,
              CommonConfigurationKeys.HADOOP_SECURITY_IDENTITY_SERVER_RPC_ADDRESS_KEY);
          conf.setBoolean(CommonConfigurationKeys.IPC_CLIENT_FALLBACK_TO_SIMPLE_AUTH_ALLOWED_KEY, true);
          secretsProtocol = new SecretsProtocolClientSideTranslatorPB(conf, address, factory, 15000);
        }
      }
    }
  }
  
  /**
   * Client should get the access token after the cached access token is expired,
   * otherwise the load of identity server and access server is to large 
   */
  public byte[] getAccessToken(byte[] tokenBytes, String protocol, String remoteAddr) throws IOException {
    /*user identity token*/
    Token identityToken = tokenFactory.createIdentityToken(getValidationSecrets(), tokenBytes); 
    if (TokenUtils.isExpired(identityToken)) {
      throw new IOException("Identity token for user " + identityToken.getPrincipal().getName() + " is expired.");
    }
    
    if (!doAuthorization(identityToken, protocol, remoteAddr)) {
      throw new IOException("Client doesn't have previlege to access requested service: " + protocol);
    }
    
    ensureConnectIdentityServer();
    if (Time.now() >= TokenUtils.getRefreshTime(getLoginToken())) {
      loginAsAuthzUser();
    }
    Secrets secrets = secretsProtocol.getSecrets(TokenUtils.getBytesOfToken(getLoginToken()), protocol);
    if(secrets == null) {
      throw new IOException("Can't get secrets for protocol: " + protocol);
    }
    
    Token accessToken = generateAccessToken(identityToken, secrets);
    return TokenUtils.getBytesOfToken(accessToken);
  }
  
  boolean doAuthorization(Token identityToken, String protocol, String remoteAddr) throws IOException {
    return policyEngine.evaluate(new EvaluationContext(identityToken, protocol, remoteAddr));
  }
  
  /**
   * Generate access token , default 'notBefore' is 5 minutes and default 
   * 'notOnOrAfter' is 60 minutes. 
   */
  Token generateAccessToken(Token userIdentityToken, Secrets secrets) throws IOException {
    long instant = Time.now();
    long fiveMins = 5 * 60 * 1000; // in milliseconds
    long expires = conf.getLong(
        HASConfiguration.HADOOP_SECURITY_TOKENAUTH_ACCESS_TOKEN_EXPIRES_KEY, 
        1 * 60 * 60 * 1000); // in milliseconds
    
    boolean tokenEncrypted = conf.getBoolean(HASConfiguration.
        HADOOP_SECURITY_TOKENAUTH_ACCESS_TOKEN_ENCRYPTED_KEY, false);
    
    Token accessToken = new AccessToken(
        secrets, "www.apache.org", 
        userIdentityToken.getPrincipal().getName(), 
        instant, 
        instant - fiveMins, instant + expires, tokenEncrypted);
    
    accessToken.getAttributes().addAll(userIdentityToken.getAttributes());
    
    return accessToken;
  }
  
  private void loginAsAuthzUser() throws IOException {
    SecurityUtil.tokenAuthLogin(conf, HASConfiguration.
        HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_AUTHENTICATION_FILE_KEY,
        HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_PRINCIPAL_KEY,null);
  }
  
  Token getLoginToken() throws IOException {
    return UserGroupInformation.getLoginUser().getIdentityToken();
  }
  
  Secrets getValidationSecrets() throws IOException {
    return UserGroupInformation.getLoginUser().getValidationSecrets();
  }

  public int run(final String[] args) throws Exception {
    loginAsAuthzUser();
    try {
      return SecurityUtil.doAsLoginUserOrFatal(new PrivilegedAction<Integer>() {
        @Override
        public Integer run() {
          try {
            return doRun(args);
          } catch (Exception t) {
            throw new RuntimeException(t);
          }
        }
      });
    } catch (RuntimeException rte) {
      throw (Exception) rte.getCause();
    }
  }
  
  public boolean isAlive() {
    return httpServer != null && httpServer.isAlive() && 
        rpcServer != null && rpcServer.isAlive();
  } 

  private int doRun(String[] args) throws HadoopIllegalArgumentException,
      IOException, InterruptedException {
    httpServer = new AuthorizationHttpServer(conf, this);
    rpcServer = new AuthorizationRPCServer(conf, this, new HASPolicyProvider());
    
    startHttpServer();
    startRPCServer();
    
    rpcServer.join();
    
    return 0;
  }

  protected void startRPCServer() throws IOException {
    rpcServer.start();
  }
  
  protected void startHttpServer() throws IOException {
    httpServer.start();
  }

  public void stop() {
    if (rpcServer != null) {
      rpcServer.stop();
    }
    try {
      if (httpServer != null) {
        httpServer.stop();
      }
    } catch (IOException e) {
    }
  }

  public static void main(String args[]) throws Exception {

    GenericOptionsParser parser =
        new GenericOptionsParser(new HASConfiguration(), args);
    AuthorizationService authorizationService = 
        AuthorizationService.create(parser.getConfiguration());

    System.exit(authorizationService.run(parser.getRemainingArgs()));
  }
}
