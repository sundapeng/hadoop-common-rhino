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

package org.apache.hadoop.security.tokenauth.jaas.auth.module;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configurable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;

public class LdapConnector implements Configurable {
  private static final Log LOG = LogFactory.getLog(LdapConnector.class);
  
  private static final SearchControls SEARCH_CONTROLS = new SearchControls();
  static {
    SEARCH_CONTROLS.setSearchScope(SearchControls.SUBTREE_SCOPE);
  }
  
  private DirContext ctx;
  private Configuration conf;
  
  private String ldapUrl;
  private boolean useSsl;
  private String keystore;
  private String keystorePass;
  private String bindUser;
  private String bindPassword;
  private String baseDN;
  private String groupSearchFilter;
  private String userSearchFilter;
  private String groupMemberAttr;
  private String groupNameAttr;
  private String searchAttrs[];
  private int dirSearchTimeout;
  
  public static int RECONNECT_RETRY_COUNT = 3;
  
  public DirContext authenticate(String username, String password) {
    Hashtable<String, String> env = new Hashtable<String, String>();
    env.put(Context.INITIAL_CONTEXT_FACTORY,
        com.sun.jndi.ldap.LdapCtxFactory.class.getName());
    env.put(Context.PROVIDER_URL, ldapUrl);
    env.put(Context.SECURITY_AUTHENTICATION, "simple");

    // Set up SSL security, if necessary
    if (useSsl) {
      env.put(Context.SECURITY_PROTOCOL, "ssl");
      System.setProperty("javax.net.ssl.keyStore", keystore);
      System.setProperty("javax.net.ssl.keyStorePassword", keystorePass);
    }

    String nameInNamespace = getNameInNamespace(username);
    if (nameInNamespace == null) {
      return null;
    }
    env.put(Context.SECURITY_PRINCIPAL, nameInNamespace);
    env.put(Context.SECURITY_CREDENTIALS, password);

    try {
      return new InitialDirContext(env);
    } catch (NamingException e) {
      return null;
    }
  }
  
  /**
   * Search groups and attributes for a user.
   * 
   * The LdapCtx which underlies the DirContext object is not thread-safe, so
   * we need to block around this whole method. The caching infrastructure will
   * ensure that performance stays in an acceptable range.
   *
   */
  public synchronized void query(String user, List<String> groups, 
      List<org.apache.hadoop.security.tokenauth.token.Attribute> attributes) {
    
    /*
     * Normal garbage collection takes care of removing Context instances when they are no longer in use. 
     * Connections used by Context instances being garbage collected will be closed automatically.
     * So in case connection is closed and gets CommunicationException, retry some times with new new DirContext/connection. 
     */
    try {
      doQuery(user, groups, attributes);
      return;
    } catch (CommunicationException e) {
      LOG.warn("Connection is closed, will try to reconnect");
    } catch (NamingException e) {
      LOG.warn("Exception trying to get groups and attributes for user " + user, e);
      return;
    }

    int retryCount = 0;
    while (retryCount ++ < RECONNECT_RETRY_COUNT) {
      //reset ctx so that new DirContext can be created with new connection
      this.ctx = null;
      
      try {
        doQuery(user, groups, attributes);
        return;
      } catch (CommunicationException e) {
        LOG.warn("Connection being closed, reconnecting failed, retryCount = " + retryCount);
      } catch (NamingException e) {
        LOG.warn("Exception trying to get groups and attributes for user " + user, e);
        return;
      }
    }
  }
  
  private void doQuery(String user, List<String> groups, 
      List<org.apache.hadoop.security.tokenauth.token.Attribute> attributes) throws NamingException {
    if (groups == null) {
      groups = new ArrayList<String>();
    }
    if (attributes == null) {
      attributes = new ArrayList<org.apache.hadoop.security.tokenauth.token.Attribute>();
    }

    DirContext ctx = getDirContext();
    
    SearchControls searchControls;
    if (searchAttrs != null && searchAttrs.length > 0) {
      searchControls = new SearchControls();
      searchControls.setTimeLimit(dirSearchTimeout);
      searchControls.setReturningAttributes(searchAttrs);
      searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    } else {
      searchControls = SEARCH_CONTROLS;
    }

    // Search for the user. We'll only ever need to look at the first result
    NamingEnumeration<SearchResult> results = ctx.search(baseDN,
        userSearchFilter,
        new Object[]{user},
        searchControls);
    if (results.hasMoreElements()) {
      SearchResult result = results.nextElement();
      String userDn = result.getNameInNamespace();
      if (searchAttrs != null && searchAttrs.length > 0) {
        convertAttributes(result.getAttributes(), attributes);
      }

      NamingEnumeration<SearchResult> groupResults =
          ctx.search(baseDN,
              "(&" + groupSearchFilter + "(" + groupMemberAttr + "={0}))",
              new Object[]{userDn},
              SEARCH_CONTROLS);
      while (groupResults.hasMoreElements()) {
        SearchResult groupResult = groupResults.nextElement();
        Attribute groupName = groupResult.getAttributes().get(groupNameAttr);
        groups.add(groupName.get().toString());
      }
    }
  }
  
  private void convertAttributes(Attributes attributes, 
      List<org.apache.hadoop.security.tokenauth.token.Attribute> tokenAttributes) 
      throws NamingException {
    NamingEnumeration<? extends Attribute> attrs = attributes.getAll();
    while(attrs.hasMore()) {
      Attribute attr = attrs.next();
      org.apache.hadoop.security.tokenauth.token.Attribute
      tokenAttribute = new org.apache.hadoop.security.tokenauth.token.Attribute(attr.getID());
      NamingEnumeration<?> attrValues = attr.getAll();
      while(attrValues.hasMore()) {
        tokenAttribute.getValues().add(attrValues.next());
      }
      tokenAttributes.add(tokenAttribute);
    }
  }
  
  private DirContext getDirContext() throws NamingException {
    if (ctx == null) {
      // Set up the initial environment for LDAP connectivity
      Hashtable<String, String> env = new Hashtable<String, String>();
      env.put(Context.INITIAL_CONTEXT_FACTORY,
          com.sun.jndi.ldap.LdapCtxFactory.class.getName());
      env.put(Context.PROVIDER_URL, ldapUrl);
      env.put(Context.SECURITY_AUTHENTICATION, "simple");

      // Set up SSL security, if necessary
      if (useSsl) {
        env.put(Context.SECURITY_PROTOCOL, "ssl");
        System.setProperty("javax.net.ssl.keyStore", keystore);
        System.setProperty("javax.net.ssl.keyStorePassword", keystorePass);
      }

      env.put(Context.SECURITY_PRINCIPAL, bindUser);
      env.put(Context.SECURITY_CREDENTIALS, bindPassword);

      ctx = new InitialDirContext(env);
    }

    return ctx;
  }
  
  private synchronized String getNameInNamespace(String user) {
    /*
     * Normal garbage collection takes care of removing Context instances when they are no longer in use. 
     * Connections used by Context instances being garbage collected will be closed automatically.
     * So in case connection is closed and gets CommunicationException, retry some times with new new DirContext/connection. 
     */
    try {
      return doGetNameInNamespace(user);
    } catch (CommunicationException e) {
      LOG.warn("Connection is closed, will try to reconnect");
    } catch (NamingException e) {
      LOG.warn("Exception trying to get name in namespace for user " + user, e);
      return null;
    }

    int retryCount = 0;
    while (retryCount ++ < RECONNECT_RETRY_COUNT) {
      //reset ctx so that new DirContext can be created with new connection
      this.ctx = null;
      
      try {
        return doGetNameInNamespace(user);
      } catch (CommunicationException e) {
        LOG.warn("Connection being closed, reconnecting failed, retryCount = " + retryCount);
      } catch (NamingException e) {
        LOG.warn("Exception trying to get name in namespace for user " + user, e);
        return null;
      }
    }
    
    return null;
  }
  
  private String doGetNameInNamespace(String user) throws NamingException {
    DirContext ctx = getDirContext();

    // Search for the user. We'll only ever need to look at the first result
    NamingEnumeration<SearchResult> results = ctx.search(baseDN,
        userSearchFilter,
        new Object[]{user},
        SEARCH_CONTROLS);
    if (results.hasMoreElements()) {
      SearchResult result = results.nextElement();
      return result.getNameInNamespace();
    }
    
    return null;
  }

  @Override
  public void setConf(Configuration conf) {
    ldapUrl = conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_URL_KEY);
    if (ldapUrl == null || ldapUrl.isEmpty()) {
      throw new RuntimeException("LDAP URL is not configured");
    }
    
    useSsl = conf.getBoolean(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_USE_SSL_KEY, 
        HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_USE_SSL_DEFAULT);
    
    if (useSsl) {
      keystore = conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_SSL_KEYSTORE_KEY, "");
      
      keystorePass =
          conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_SSL_KEYSTORE_PASSWORD_KEY, "");
      if (keystorePass.isEmpty()) {
        keystorePass = extractPassword(
          conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_SSL_KEYSTORE_PASSWORD_FILE_KEY, ""));
      }
    }
    
    bindUser = conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_BIND_USER_KEY, "");
    bindPassword = conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_BIND_PASSWORD_KEY, "");
    if (bindPassword.isEmpty()) {
      bindPassword = extractPassword(
          conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_BIND_PASSWORD_FILE_KEY, ""));
    }
    
    baseDN = conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_BASE_DN_KEY, "");
    groupSearchFilter =
        conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_GROUP_SERACH_FILTER_KEY, 
            HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_GROUP_SERACH_FILTER_DEFAULT);
    userSearchFilter =
        conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_USER_SERACH_FILTER_KEY, 
            HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_USER_SERACH_FILTER_DEFAULT);
    groupMemberAttr =
        conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_GROUP_MEMBERSHIP_ATTR_KEY, 
            HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_GROUP_MEMBERSHIP_ATTR_DEFAULT);
    groupNameAttr =
        conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_GROUP_NAME_ATTR_KEY, 
            HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_GROUP_NAME_ATTR_DEFAULT);
    
    String searchAttrsConf = conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_QUERY_ATTRIBUTES_KEY);
    if(searchAttrsConf != null) {
      searchAttrs = searchAttrsConf.split(","); 
    }

    dirSearchTimeout = conf.getInt(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_DIRECTORY_SEARCH_TIMEOUT_KEY, 
        HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_DIRECTORY_SEARCH_TIMEOUT_DEFAULT);
    SEARCH_CONTROLS.setTimeLimit(dirSearchTimeout);
  }

  @Override
  public Configuration getConf() {
    return conf;
  }

  private String extractPassword(String pwFile) {
    if (pwFile.isEmpty()) {
      // If there is no password file defined, we'll assume that we should do
      // an anonymous bind
      return "";
    }
    
    Reader reader = null;
    try {
      StringBuilder password = new StringBuilder();
      reader = new FileReader(pwFile);
      int c = reader.read();
      while (c > -1) {
        password.append((char)c);
        c = reader.read();
      }
      return password.toString().trim();
    } catch (IOException ioe) {
      throw new RuntimeException("Could not read password file: " + pwFile, ioe);
    } finally {
      if (reader != null) {
        try {
          reader.close();
        } catch (IOException e) {
        }
      }
    }
  }
}
