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

package org.apache.hadoop.security.tokenauth.jaas;
/*
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import javax.naming.directory.DirContext;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.apache.hadoop.security.tokenauth.jaas.auth.module.LdapConnector;
import org.apache.hadoop.security.tokenauth.token.Attribute;
*/
import org.junit.Test;

public class TestLdapConnector {

  @Test
  public void testConnector() throws Exception {
/*
    Configuration conf = new HASConfiguration();
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_URL_KEY, "ldap://10.239.47.131");
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_BIND_USER_KEY, "CN=HadoopAdmin,CN=Users,DC=ta,DC=sh,DC=intel,DC=com");
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_BIND_PASSWORD_KEY, "Front123");
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_BASE_DN_KEY, "CN=Users,DC=ta,DC=sh,DC=intel,DC=com");
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_QUERY_ATTRIBUTES_KEY, "displayName,userPrincipalName");
    
    LdapConnector ldapConnector = new LdapConnector();
    ldapConnector.setConf(conf);
    
    DirContext dirContext = ldapConnector.authenticate("yarn", "Front123");
    assertTrue(dirContext != null);
    
    List<String> groups = new ArrayList<String>();
    List<Attribute> attributes = new ArrayList<Attribute>();
    ldapConnector.query("hdfs", groups, attributes);
    
    System.out.println(groups.size());
    System.out.println(attributes.size());
*/
  }
}
