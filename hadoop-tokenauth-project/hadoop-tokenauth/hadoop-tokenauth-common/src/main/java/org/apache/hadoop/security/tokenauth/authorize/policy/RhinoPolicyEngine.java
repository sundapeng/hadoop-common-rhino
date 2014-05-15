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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;

public class RhinoPolicyEngine implements PolicyEngine {
  public static final String PROTOCOL = "${protocol}";
  public static final String IP = "${ip}";
  public static final String USER = "${user}";
  public static final String GROUPS = "${groups}";
  
  private final Context context;
  private final Scriptable sharedScope;
  /**
   * policy is java script function named "evaluate".
   * example:
   * 
   *    function evaluate() {
   *      var age = ${age};
   *      var result = false;
   *      if(age > 60) {
   *        result = true;
   *      }
   *      return result;
   *    }
   **/
  private final String policy;
  private List<String> policySnippets;
  
  RhinoPolicyEngine(String policyConf) {
    if (policyConf == null) {
      throw new NullPointerException("policy conf can't be null");
    }
    this.policy = loadPolicy(policyConf) + "\n" + "evaluate();";
    context = Context.enter();
    sharedScope = context.initStandardObjects();
    policySnippets = getPolicySnippets();
  }
  
  InputStream getPolicyInputStream(String policyConf) {
	  return getClass().getResourceAsStream(policyConf);
  }
  
  String loadPolicy(String policyConf) {
    InputStream in = getPolicyInputStream(policyConf);
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[1024];
      int n = 0;
      while((n = in.read(buffer)) > -1) {
        out.write(buffer, 0, n);
      }
      
      return out.toString("utf-8");
    } catch (IOException e) {
      throw new RuntimeException("Can't load policy conf");
    } finally {
      if (in != null) {
        try {
          in.close();
        } catch (IOException e) {
          
        }
      }
    }
  }
  
  List<String> getPolicySnippets() {
    List<String> snippets = new ArrayList<String>();
    int varStart = 0;
    String tmp = policy;
    while((varStart = tmp.indexOf("${")) > -1) {
      String snippet = tmp.substring(0, varStart);
      snippets.add(snippet);
      tmp = tmp.substring(varStart);
      int varEnd = tmp.indexOf("}");
      if (varEnd < 0) 
        throw new RuntimeException("Incorret format of policy");
      String var = tmp.substring(0, varEnd + 1);
      snippets.add(var);
      tmp = tmp.substring(varEnd + 1);
    }
    snippets.add(tmp);
    return snippets;
  }
  
  private String apply(EvaluationContext context) {
    StringBuffer appliedPolicy = new StringBuffer();
    for(String snippet : policySnippets) {
      if (snippet.startsWith("${")) {
        if (snippet.equalsIgnoreCase(PROTOCOL)) {
          appliedPolicy.append("\"" + context.getProtocol() + "\"");
        } else if (snippet.equalsIgnoreCase(IP)) {
          throw new RuntimeException("Not support");
        } else if (snippet.equalsIgnoreCase(USER)) {
          appliedPolicy.append("\"" + context.getUser() + "\"");
        } else if (snippet.equalsIgnoreCase(GROUPS)) {
          appliedPolicy.append(toJSObjectValue(context.getGroups()));
        } else {
          String var = snippet.substring(2, snippet.length() -1);
          appliedPolicy.append(toJSObjectValue(context.getVariableValues(var)));
        }
      } else {
        appliedPolicy.append(snippet);
      }
    }
    
    return appliedPolicy.toString();
  }
  
  private String toJSObjectValue(String[] groups) {
    StringBuffer js = new StringBuffer();
    js.append("[");
    if (groups != null && groups.length > 0) {
      boolean first = true;
      for(String group : groups) {
        if(first) {
          first = false;
        } else {
          js.append(",");
        }
        js.append("\"").append(group).append("\"");
      }
    }
    js.append("]");
    return js.toString();
  }
  
  public String toJSObjectValue(Set<Object> values) {
    if (values != null && values.size() > 0) {
      StringBuffer js = new StringBuffer();
      js.append("[");
      boolean first = true;
      for (Object value : values) {
        if (!(value instanceof String)) {
          return String.valueOf(value);
        }
        if(first) {
          first = false;
        } else {
          js.append(",");
        }
        js.append("\"").append(value).append("\"");
      }
      js.append("]");
      return js.toString();
    }
    
    return "null";
  }

  @Override
  public boolean evaluate(EvaluationContext evaluationCtx) throws IOException {
    Context cx = Context.enter();
    try {
      Scriptable scope = cx.newObject(sharedScope);
      scope.setPrototype(sharedScope);
      scope.setParentScope(null);
      
      String appliedPolicy = apply(evaluationCtx);
      Object result = cx.evaluateString(scope, appliedPolicy, "<policy>", 1, null);
      return Boolean.parseBoolean(Context.toString(result)); 
    } finally {
      Context.exit();
    }
  }
  
  @Override
  protected void finalize() {
    Context.exit();
  }
}
