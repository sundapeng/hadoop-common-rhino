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

package org.apache.hadoop.security.tokenauth.authorize.policy;

import java.io.File;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.token.Attribute;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.impl.IdentityToken;
import org.junit.Test;

public class TestPolicyEngine {
  
  @Test
  public void testRhinoPolicyEngine() throws Exception {
    String policy = 
        "function evaluate() {\n" +
        "  var user = ${user};\n" +
        "  var age = ${age};\n" +
        "  var result = false;\n" +
        "  if(user == \"hdfs\") {\n" +
        "    result = true;\n" +
        "  }\n" +
        "  if(age < 60) {\n" +
        "    result = false;\n" +
        "  }\n" +
        "  return result;\n" +
        "}";
    String policyConf = "/tmp/policy_file";
    File file = new File(policyConf);
    FileOutputStream fout = new FileOutputStream(file);
    fout.write(policy.getBytes());
    fout.close();
    
    PolicyEngine policyEngine = new MiniPolicyEngine(policyConf);
    Token token = new IdentityToken(new Secrets() {

      @Override
      public SecretKey getSecretKey() {
        return null;
      }

      @Override
      public PublicKey getPublicKey() {
        return null;
      }

      @Override
      public PrivateKey getPrivateKey() {
        return null;
      }
      
    }, "www.apache.org", "hdfs", 0, 0, 0);
    Attribute attribute = new Attribute("age");
    attribute.getValues().add(61);
    token.getAttributes().add(attribute);
    EvaluationContext context = new EvaluationContext(token);
    
    System.out.println(policyEngine.evaluate(context));
    
    file.delete();
  }

}
