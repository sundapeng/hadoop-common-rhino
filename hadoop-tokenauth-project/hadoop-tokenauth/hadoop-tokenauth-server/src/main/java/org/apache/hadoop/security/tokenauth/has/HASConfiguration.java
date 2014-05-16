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

import org.apache.hadoop.conf.Configuration;

public class HASConfiguration extends Configuration {
  
  private static final String HAS_DEFAULT_XML_FILE = "has-default.xml";
  private static final String HAS_SITE_XML_FILE = "has-site.xml";
  
  static {
    Configuration.addDefaultResource(HAS_DEFAULT_XML_FILE);
    Configuration.addDefaultResource(HAS_SITE_XML_FILE);
  }
  
  public static final String HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX = 
      "hadoop.security.tokenauth";
    
  public static final String HADOOP_SECURITY_TOKENAUTH_AUTHENTICATORS_KEY = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".authenticators";
  public static final String HADOOP_SECURITY_TOKENAUTH_AUTHENTICATOR_PREFIX = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".authenticator";
  public static final String HADOOP_SECURITY_TOKENAUTH_AUTHENTICATOR_CONTROLFLAG = 
      ".controlflag";
  public static final String HADOOP_SECURITY_TOKENAUTH_AUTHENTICATOR_LDAP_CONTROLFLAG_KEY = 
      HADOOP_SECURITY_TOKENAUTH_AUTHENTICATOR_PREFIX + ".ldap.controlflag";
  
  /**LDAP authenticator**/
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_CONFIG_PREFIX = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".ldap";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_URL_KEY = 
      HADOOP_SECURITY_TOKENAUTH_LDAP_CONFIG_PREFIX + ".url";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_USE_SSL_KEY = 
      HADOOP_SECURITY_TOKENAUTH_LDAP_CONFIG_PREFIX + ".ssl";
  public static final boolean HADOOP_SECURITY_TOKENAUTH_LDAP_USE_SSL_DEFAULT = false;
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_SSL_KEYSTORE_KEY = 
      HADOOP_SECURITY_TOKENAUTH_LDAP_CONFIG_PREFIX + ".ssl.keystore";  
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_SSL_KEYSTORE_PASSWORD_KEY = 
      HADOOP_SECURITY_TOKENAUTH_LDAP_SSL_KEYSTORE_KEY + ".password";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_SSL_KEYSTORE_PASSWORD_FILE_KEY = 
      HADOOP_SECURITY_TOKENAUTH_LDAP_SSL_KEYSTORE_PASSWORD_KEY + ".file";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_BIND_USER_KEY = 
      HADOOP_SECURITY_TOKENAUTH_LDAP_CONFIG_PREFIX + ".bind.user";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_BIND_PASSWORD_KEY = 
      HADOOP_SECURITY_TOKENAUTH_LDAP_CONFIG_PREFIX + ".bind.password";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_BIND_PASSWORD_FILE_KEY = 
      HADOOP_SECURITY_TOKENAUTH_LDAP_BIND_PASSWORD_KEY + ".file";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_BASE_DN_KEY = 
      HADOOP_SECURITY_TOKENAUTH_LDAP_CONFIG_PREFIX + ".base.dn";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_USER_SERACH_FILTER_KEY = 
      HADOOP_SECURITY_TOKENAUTH_LDAP_CONFIG_PREFIX + ".user.search.filter";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_USER_SERACH_FILTER_DEFAULT = 
      "(&(objectClass=user)(sAMAccountName={0}))";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_GROUP_SERACH_FILTER_KEY = 
      HADOOP_SECURITY_TOKENAUTH_LDAP_CONFIG_PREFIX + ".group.search.filter";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_GROUP_SERACH_FILTER_DEFAULT = 
      "(objectClass=group)";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_GROUP_NAME_ATTR_KEY = 
      HADOOP_SECURITY_TOKENAUTH_LDAP_CONFIG_PREFIX + ".group.name.attr";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_GROUP_NAME_ATTR_DEFAULT = "cn";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_GROUP_MEMBERSHIP_ATTR_KEY = 
      HADOOP_SECURITY_TOKENAUTH_LDAP_CONFIG_PREFIX + ".group.membership.attr";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_GROUP_MEMBERSHIP_ATTR_DEFAULT = "member";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_QUERY_ATTRIBUTES_KEY =
      HADOOP_SECURITY_TOKENAUTH_LDAP_CONFIG_PREFIX + ".query.attrs";
  public static final String HADOOP_SECURITY_TOKENAUTH_LDAP_DIRECTORY_SEARCH_TIMEOUT_KEY = 
      HADOOP_SECURITY_TOKENAUTH_LDAP_CONFIG_PREFIX + ".directory.search.timeout";
  public static final int HADOOP_SECURITY_TOKENAUTH_LDAP_DIRECTORY_SEARCH_TIMEOUT_DEFAULT = 10000;
  /**LDAP authenticator end**/
  
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_CONFIG_PREFIX = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".identity.server";
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_KEYTAB_KEY = 
      HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_CONFIG_PREFIX + ".keytab";
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_PRINCIPAL_KEY =
      HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_CONFIG_PREFIX + ".principal";
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_HTTP_KEYTAB_KEY = 
      HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_CONFIG_PREFIX + ".http.keytab";
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_HTTP_PRINCIPAL_KEY = 
      HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_CONFIG_PREFIX + ".http.principal";
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_ADMIN_KEY = 
      HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_CONFIG_PREFIX + ".admin";
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_LISTENER_THREAD_COUNT_KEY = 
      HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_CONFIG_PREFIX + ".listener.thread.count";
  public static final int HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_LISTENER_THREAD_COUNT_DEFAULT = 50;
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_ISSUEDTOKENS_PERSISTENT_FILE_KEY = 
      HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_CONFIG_PREFIX + ".issuedtokens.persistent.file";
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_ISSUEDTOKENS_PERSISTENT_INTERVAL = 
      HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_CONFIG_PREFIX + ".issuedtokens.persistent.interval";
  
  public static final String HADOOP_SECURITY_TOKENAUTH_SECRETSMANAGER_KEYSTORE_KEY = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".secretsmanager.keystore";
  public static final String HADOOP_SECURITY_TOKENAUTH_SECRETSMANAGER_KEYSTORE_SECRET_KEY = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".secretsmanager.keystore.secret.file";
  
  public static final String HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_CONFIG_PREFIX = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".authorization.server";
  public static final String HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_PRINCIPAL_KEY = 
      HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_CONFIG_PREFIX + ".principal";
  public static final String HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_AUTHENTICATION_FILE_KEY = 
      HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_CONFIG_PREFIX + ".authentication.file";
  public static final String HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_LISTENER_THREAD_COUNT_KEY = 
      HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_CONFIG_PREFIX + ".listener.thread.count";
  public static final int HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_LISTENER_THREAD_COUNT_DEFAULT = 50;
  
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_TOKEN_ENCRYPTED_KEY = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".identity.token.encrypted";
  public static final String HADOOP_SECURITY_TOKENAUTH_ACCESS_TOKEN_ENCRYPTED_KEY =
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".access.token.encrypted";
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_TOKEN_RENEWABLE_KEY =
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".identity.token.renewable";
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_TOKEN_MAX_RENEW_TIME_KEY =
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".identity.token.max.renew.time";
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_TOKEN_MAX_LIFETIME =
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".identity.token.max.lifetime";
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_TOKEN_RENEW_EXTENSION_PERIOD_KEY =
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".identity.token.renew.extension.period";

  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVICE_PROTOCOL_ACL = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".identity.service.protocol.acl";
  public static final String HADOOP_SECURITY_TOKENAUTH_SECRETS_PROTOCOL_ACL = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".secrets.protocol.acl";
  public static final String HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVICE_PROTOCOL_ACL = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".authorization.service.protocol.acl";
  
  /* the expires of identity token, in milliseconds, default is 24 hours */
  public static final String HADOOP_SECURITY_TOKENAUTH_IDENTITY_TOKEN_EXPIRES_KEY = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".identity.token.expires";
  
  /* the expires of access token, in milliseconds, default is 15 minutes */
  public static final String HADOOP_SECURITY_TOKENAUTH_ACCESS_TOKEN_EXPIRES_KEY = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".access.token.expires";
  
  public static final String HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_ENGINE_IMPL = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".authorization.engine.impl";
  public static final String HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_ENGINE_IMPL_DEFAULT = 
      "org.apache.hadoop.security.tokenauth.authorize.policy.RhinoPolicyEngine";
  public static final String HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_ENGINE_IMPL_MINI = 
      "org.apache.hadoop.security.tokenauth.authorize.policy.MiniPolicyEngine";
  public static final String HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_POLICY = 
      HADOOP_SECURITY_TOKENAUTH_CONFIG_PREFIX + ".authorization.policy";
  public static final String HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_POLICY_DEFAULT = 
      "/authorization-policy-script";
  
  public HASConfiguration() {
    super();
  }
  
  public HASConfiguration(Configuration conf) {
    super(conf);
    if (! (conf instanceof HASConfiguration)) {
      this.reloadConfiguration();
    }
  }

  public static void init() {
  }
}
