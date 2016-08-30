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
package org.apache.hadoop.security.tokenauth.kerberos;

import java.util.HashMap;
import java.util.Map;
import javax.security.auth.login.AppConfigurationEntry;

import static org.apache.hadoop.security.tokenauth.kerberos.KerberosUtil.IBM_JAVA;

public class KerberosLoginConfiguration
    extends javax.security.auth.login.Configuration {

  String keytab;
  String principal;

  public KerberosLoginConfiguration() {
  }

  public KerberosLoginConfiguration(String keytab, String principal) {
    this.keytab = keytab;
    this.principal = principal;
  }

  private final static String USER_KERBEROS_CONFIG_NAME = "user-kerberos";
  private final static String KEYTAB_KERBEROS_CONFIG_NAME = "keytab-kerberos";

  private static final Map<String, String> BASIC_JAAS_OPTIONS =
      new HashMap<String, String>();
  static {
    String jaasEnvVar = System.getenv("HADOOP_JAAS_DEBUG");
    if (jaasEnvVar != null && "true".equalsIgnoreCase(jaasEnvVar)) {
      BASIC_JAAS_OPTIONS.put("debug", "true");
    }
  }

  private static final Map<String, String> USER_KERBEROS_OPTIONS =
      new HashMap<String, String>();

  static {
    if (IBM_JAVA) {
      USER_KERBEROS_OPTIONS.put("useDefaultCcache", "true");
    } else {
      USER_KERBEROS_OPTIONS.put("doNotPrompt", "true");
      USER_KERBEROS_OPTIONS.put("useTicketCache", "true");
    }
    String ticketCache = System.getenv("KRB5CCNAME");
    if (ticketCache != null) {
      if (IBM_JAVA) {
        // The first value searched when "useDefaultCcache" is used.
        System.setProperty("KRB5CCNAME", ticketCache);
      } else {
        USER_KERBEROS_OPTIONS.put("ticketCache", ticketCache);
      }
    }
    USER_KERBEROS_OPTIONS.put("renewTGT", "true");
    USER_KERBEROS_OPTIONS.putAll(BASIC_JAAS_OPTIONS);
  }

  private static final AppConfigurationEntry USER_KERBEROS_LOGIN =
      new AppConfigurationEntry(KerberosUtil.getKrb5LoginModuleName(),
          AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL,
          USER_KERBEROS_OPTIONS);
  private static final Map<String, String> KEYTAB_KERBEROS_OPTIONS =
      new HashMap<String, String>();

  static {
    if (IBM_JAVA) {
      KEYTAB_KERBEROS_OPTIONS.put("credsType", "both");
    } else {
      KEYTAB_KERBEROS_OPTIONS.put("doNotPrompt", "true");
      KEYTAB_KERBEROS_OPTIONS.put("useKeyTab", "true");
      KEYTAB_KERBEROS_OPTIONS.put("storeKey", "true");
    }
    KEYTAB_KERBEROS_OPTIONS.put("refreshKrb5Config", "true");
    KEYTAB_KERBEROS_OPTIONS.putAll(BASIC_JAAS_OPTIONS);
  }

  private static final AppConfigurationEntry KEYTAB_KERBEROS_LOGIN =
      new AppConfigurationEntry(KerberosUtil.getKrb5LoginModuleName(),
          AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
          KEYTAB_KERBEROS_OPTIONS);

  private static final AppConfigurationEntry[] USER_KERBEROS_CONF =
      new AppConfigurationEntry[]{USER_KERBEROS_LOGIN,};
  private static final AppConfigurationEntry[] KEYTAB_KERBEROS_CONF =
      new AppConfigurationEntry[]{KEYTAB_KERBEROS_LOGIN};

  @Override
  public AppConfigurationEntry[] getAppConfigurationEntry(String appName) {
    if (USER_KERBEROS_CONFIG_NAME.equals(appName)) {
      return USER_KERBEROS_CONF;
    } else if (KEYTAB_KERBEROS_CONFIG_NAME.equals(appName)) {
      KEYTAB_KERBEROS_OPTIONS.put("keyTab", keytab);
      KEYTAB_KERBEROS_OPTIONS.put("principal", principal);
      return KEYTAB_KERBEROS_CONF;
    }
    throw null;
  }
}