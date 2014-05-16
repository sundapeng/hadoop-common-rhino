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
package org.apache.hadoop.security.tokenauth.has.identity.rest;

import java.io.IOException;

import javax.servlet.ServletContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.api.rest.JsonHelper;
import org.apache.hadoop.security.tokenauth.api.rest.RESTParams;
import org.apache.hadoop.security.tokenauth.has.HASClientImpl;
import org.apache.hadoop.security.tokenauth.has.identity.IdentityService;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;

@Path("")
public class IdentityRESTServices {
  
  public static final String PATH_PREFIX = RESTParams.PATH_V1;;
  
  private static final Log LOG = LogFactory.getLog(IdentityRESTServices.class);
  
  private @Context ServletContext context;
  
  IdentityService getIdentityService() {
    return (IdentityService)context.getAttribute("localidentity");
  }
  
  @GET
  @Path("/hello")
  @Produces({MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_JSON})
  public Response hello() {
    String js = JsonHelper.toJsonString("msg", "hello tokenauth");
    return Response.ok(js).type(MediaType.APPLICATION_JSON).build();
  }
  
  @POST
  @Path("/authenticate")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces({MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_JSON})
  public Response authenticate(String jsonString) throws IOException {
    LOG.info("New authenticate request: "+jsonString);
    IdentityRequest identityRequest = JsonHelper.toIdentityRequest(jsonString);
    IdentityResponse identityResponse = getIdentityService().authenticate(identityRequest);
    String json = JsonHelper.toJsonString(identityResponse);
    return Response.ok(json).type(MediaType.APPLICATION_JSON).build();
  }
  
  @POST
  @Path("/getSecrets")
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces({MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_JSON})
  public Response getSecrets(
      @FormParam(RESTParams.IDENTITY_TOKEN) String identityToken,
      @FormParam(RESTParams.PROTOCOL) String protocol) throws IOException {
    Secrets secrets = getIdentityService().getSecrets(
        TokenUtils.decodeToken(identityToken), protocol);
    String json = JsonHelper.toJsonString(secrets);
    return Response.ok(json).type(MediaType.APPLICATION_JSON).build();
  }
  
  @POST
  @Path("/renewToken")
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces({MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_JSON})
  public Response renewToken(
      @FormParam(RESTParams.IDENTITY_TOKEN) String identityToken,
      @FormParam(RESTParams.TOKEN_ID) long tokenId) throws IOException {
    byte[] token = getIdentityService().renewToken(TokenUtils.decodeToken(identityToken), tokenId);
    String json = JsonHelper.toJsonString(RESTParams.IDENTITY_TOKEN, 
        TokenUtils.encodeToken(token));
    return Response.ok(json).type(MediaType.APPLICATION_JSON).build();
  }
  
  @POST
  @Path("/cancelToken")
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces({MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_JSON})
  public Response cancelToken(
      @FormParam(RESTParams.IDENTITY_TOKEN) String identityToken,
      @FormParam(RESTParams.TOKEN_ID) long tokenId) throws IOException {
    getIdentityService().cancelToken(TokenUtils.decodeToken(identityToken), tokenId);
    return Response.ok().type(MediaType.APPLICATION_OCTET_STREAM).build();
  }
}
