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
package org.apache.hadoop.security.tokenauth.has.authorization.rest;

import java.io.IOException;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.hadoop.security.tokenauth.api.rest.JsonHelper;
import org.apache.hadoop.security.tokenauth.api.rest.RESTParams;
import org.apache.hadoop.security.tokenauth.has.RestUtil;
import org.apache.hadoop.security.tokenauth.has.authorization.AuthorizationService;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;

@Path("")
public class AuthorizationRESTServices {
  
  public static final String PATH_PREFIX = RESTParams.PATH_V1;
  
  private @Context ServletContext context;
  private @Context HttpServletRequest request;
  
  AuthorizationService getAuthorizationService() {
    return (AuthorizationService)context.getAttribute("localauthorization");
  }
  
  @GET
  @Path("/hello")
  @Produces({MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_JSON})
  public Response hello() {
    String js = JsonHelper.toJsonString("msg", "hello tokenauth");
    return Response.ok(js).type(MediaType.APPLICATION_JSON).build();
  }
  
  @POST
  @Path("/authorize")
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces({MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_JSON})
  public Response authorize(
      @FormParam(RESTParams.IDENTITY_TOKEN) String identityToken,
      @FormParam(RESTParams.PROTOCOL) String protocol) throws IOException {
    String remoteAddr = request.getRemoteAddr();
    byte[] accessToken;
    try{
      accessToken = getAuthorizationService().getAccessToken(TokenUtils.decodeToken(identityToken),
          protocol, remoteAddr);
    }
    catch(IOException e){
      return RestUtil.handleException(e);
    }
    String json = JsonHelper.toJsonString(RESTParams.ACCESS_TOKEN, 
        TokenUtils.encodeToken(accessToken));
    return Response.ok(json).type(MediaType.APPLICATION_JSON).build();
  }

}
