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

package org.apache.hadoop.security.tokenauth.has.authorization.http;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;

import javax.servlet.ServletContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.http.HttpConfig;
import org.apache.hadoop.http.HttpServer2;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.tokenauth.api.web.WEBParams;
import org.apache.hadoop.security.tokenauth.has.authorization.AuthorizationService;
import org.apache.hadoop.security.tokenauth.has.authorization.rest.AuthorizationRESTServices;

public class AuthorizationHttpServer {
  public static final Log LOG = LogFactory.getLog(
      AuthorizationHttpServer.class);
  
  public static final String AUTHORIZATION_ATTRIBUTE_KEY = "localauthorization";
  public static final String CURRENT_CONF = "current.conf";
  
  private HttpServer2 httpServer;
  private final Configuration conf;
  private final AuthorizationService authorizationService;
  
  private int infoPort;
  
  public AuthorizationHttpServer(Configuration conf, AuthorizationService authorizationService) {
    this.conf = conf;
    this.authorizationService = authorizationService;
    conf.set("hadoop.http.authentication.type", "simple");
  }
  
  public void start() throws IOException {
    final InetSocketAddress bindAddr = getAddress(conf);
    httpServer = new HttpServer2.Builder().setName("authorization")
        .addEndpoint(URI.create("http://"+NetUtils.getHostPortString(bindAddr)))
        .setFindPort(false).setConf(conf).setSecurityEnabled(false).build();
    httpServer.setAttribute(AUTHORIZATION_ATTRIBUTE_KEY, authorizationService);
    httpServer.setAttribute(CURRENT_CONF, conf);
    
    final String pathSpec = AuthorizationRESTServices.PATH_PREFIX + "/*";
    // add identity rest packages
    httpServer.addJerseyResourcePackage(
        AuthorizationRESTServices.class.getPackage().getName(), pathSpec);
    
    httpServer.addInternalServlet("authorize", 
        WEBParams.AUTHORIZE_SERVLET_PATH_SPEC, AuthorizationServlet.class, false);
    
    httpServer.start();
    
    infoPort = httpServer.getPort();

    LOG.info("Authorization Web-server up at: " + bindAddr + ":" + infoPort);
  }
  
  public void stop() throws IOException {
    if (httpServer != null) {
      try {
        httpServer.stop();
      } catch (Exception e) {
        throw new IOException(e);
      }
    }
  }
  
  public boolean isAlive() {
    return httpServer != null && httpServer.isAlive();
  }
  
  /**
   * Return the actual address bound to by the running server.
   */
  @Deprecated
  public InetSocketAddress getAddress() {
    // Mark as deprecated because HttpServer2 can bind multiple endpoints.
    // This method return the first address.
    InetSocketAddress addr = httpServer.getConnectorAddress(0);
    assert addr.getPort() != 0;
    return addr;
  }
  
  private static InetSocketAddress getAddress(Configuration conf) {
    return NetUtils.createSocketAddr(getAuthorizationHttpServerAddress(conf),
        CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_HTTP_PORT_DEFAULT,
        CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_HTTP_ADDRESS_KEY);
  }
  
  public static String getAuthorizationHttpServerAddress(Configuration conf) {
    return conf.get(CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_HTTP_ADDRESS_KEY, 
        CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_HTTP_ADDRESS_DEFAULT);
  }
  
  public static String getAccessTokenUrl(Configuration conf) {
    if (conf == null) conf = new Configuration();
    return conf
        .get(CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_HTTP_POLICY_KEY,
            "HTTPS").equalsIgnoreCase("HTTPS") ? "https://" : "http://"
        + getAuthorizationHttpServerAddress(conf) + WEBParams.AUTHORIZE_SERVLET_PATH_SPEC;
  }
  
  public static AuthorizationService getServiceFromContext(ServletContext context)
      throws IOException {
    return (AuthorizationService)context.getAttribute(AUTHORIZATION_ATTRIBUTE_KEY); 
  }
  
  public static Configuration getConfFromContext(ServletContext context) {
    return (Configuration) context.getAttribute(CURRENT_CONF);
  }
}
