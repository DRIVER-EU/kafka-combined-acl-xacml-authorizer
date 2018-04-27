/**
 * Copyright 2018 Thales Services SAS.
 *
 * This file is part of AuthzForce CE.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ow2.authzforce.kafka.pep;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Collections;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.apache.cxf.ext.logging.LoggingFeature;
import org.apache.cxf.feature.Feature;
import org.apache.cxf.jaxrs.client.WebClient;
import org.json.JSONObject;
import org.ow2.authzforce.jaxrs.util.JsonRiJaxrsProvider;
import org.ow2.authzforce.xacml.json.model.LimitsCheckingJSONObject;
import org.ow2.authzforce.xacml.json.model.Xacml3JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableMap;

import freemarker.cache.StringTemplateLoader;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateExceptionHandler;
import kafka.network.RequestChannel.Session;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import kafka.security.auth.SimpleAclAuthorizer;

public class CombinedXacmlAclAuthorizer extends SimpleAclAuthorizer
{
	private static final Logger LOGGER = LoggerFactory.getLogger(CombinedXacmlAclAuthorizer.class);

	/**
	 * Name of Kafka configuration property specifying the RESTful XACML PDP resource's URL (e.g. https://services.example.com/pdp), as defined by REST Profile of XACML, §2.2.2
	 */
	public static final String XACML_PDP_URL = "org.ow2.authzforce.kafka.pep.xacml.pdp.url";

	/**
	 * Name of Kafka configuration property specifying the XACML Request template
	 */
	public static final String XACML_REQUEST_TEMPLATE_CFG_PROPERTY_NAME = "org.ow2.authzforce.kafka.pep.xacml.req.tmpl";

	private static final int MAX_JSON_STRING_LENGTH = 1000;

	/*
	 * Max number of child elements - key-value pairs or items - in JSONObject/JSONArray
	 */
	private static final int MAX_JSON_CHILDREN_COUNT = 1000;

	private static final int MAX_JSON_DEPTH = 10;

	private WebClient pdpClient = null;

	private Template xacmlReqTmpl = null;

	@Override
	public void configure(Map<String, ?> authorizerProperties)
	{
		synchronized (CombinedXacmlAclAuthorizer.class)
		{
			super.configure(authorizerProperties);

			final Object xacmlPdpUrlObj = authorizerProperties.get(XACML_PDP_URL);
			if (xacmlPdpUrlObj == null)
			{
				LOGGER.info("Configuration property '{}' undefined -> XACML evaluation disabled, KAFKA ACL enabled only.", XACML_PDP_URL);
				return;
			}

			if (!(xacmlPdpUrlObj instanceof String))
			{
				throw new IllegalArgumentException(this + ": authorizer configuration property '" + XACML_PDP_URL + "' is not a String");
			}

			final String xacmlPdpUrlStr = (String) xacmlPdpUrlObj;
			LOGGER.debug("XACML PDP URL set from authorizer configuration property '{}': {}", XACML_PDP_URL, xacmlPdpUrlStr);

			pdpClient = WebClient
			        .create(xacmlPdpUrlStr, Collections.singletonList(new JsonRiJaxrsProvider(/* extra parameters */)),
			                LOGGER.isDebugEnabled() ? Collections.singletonList(new LoggingFeature()) : Collections.<Feature>emptyList(), null /* clientConfClasspathLocation */)
			        .type(MediaType.APPLICATION_JSON_TYPE).accept(MediaType.APPLICATION_JSON_TYPE);

			final Object xacmlReqTmplObj = authorizerProperties.get(XACML_REQUEST_TEMPLATE_CFG_PROPERTY_NAME);
			if (!(xacmlReqTmplObj instanceof String))
			{
				throw new IllegalArgumentException(this + ": authorizer configuration property '" + XACML_REQUEST_TEMPLATE_CFG_PROPERTY_NAME + "' is missing or not a String");
			}

			final String xacmlReqTmplStr = (String) xacmlReqTmplObj;
			LOGGER.debug("Loading XACML Request template from authorizer configuration property '{}': {}", XACML_REQUEST_TEMPLATE_CFG_PROPERTY_NAME, xacmlReqTmplStr);

			final JSONObject jsonRequest = new LimitsCheckingJSONObject(new StringReader(xacmlReqTmplStr), MAX_JSON_STRING_LENGTH, MAX_JSON_CHILDREN_COUNT, MAX_JSON_DEPTH);
			if (!jsonRequest.has("Request"))
			{
				throw new IllegalArgumentException("Invalid XACML JSON Request file specified by '" + XACML_REQUEST_TEMPLATE_CFG_PROPERTY_NAME + "'. Root key is not 'Request' as expected.");
			}

			Xacml3JsonUtils.REQUEST_SCHEMA.validate(jsonRequest);

			// Create your Configuration instance, and specify if up to what FreeMarker
			// version (here 2.3.27) do you want to apply the fixes that are not 100%
			// backward-compatible. See the Configuration JavaDoc for details.
			final Configuration xacmlReqTmplEngineCfg = new Configuration(Configuration.VERSION_2_3_23);
			// Set the preferred charset template files are stored in. UTF-8 is
			// a good choice in most applications:
			xacmlReqTmplEngineCfg.setDefaultEncoding("UTF-8");

			// Sets how errors will appear.
			// During web page *development* TemplateExceptionHandler.HTML_DEBUG_HANDLER is
			// better.
			xacmlReqTmplEngineCfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);

			// Don't log exceptions inside FreeMarker that it will thrown at you anyway:
			// XACML_REQ_TMPL_ENGINE_CFG.setLogTemplateExceptions(false);

			// Wrap unchecked exceptions thrown during template processing into
			// TemplateException-s.
			// FREEMARKER_CFG.setWrapUncheckedExceptions(true);

			final StringTemplateLoader xacmlReqTmplLoader = new StringTemplateLoader();
			xacmlReqTmplLoader.putTemplate(this.toString(), xacmlReqTmplStr);
			xacmlReqTmplEngineCfg.setTemplateLoader(xacmlReqTmplLoader);

			try
			{
				xacmlReqTmpl = xacmlReqTmplEngineCfg.getTemplate(this.toString());
			}
			catch (final IOException e)
			{
				throw new RuntimeException("Error getting XACML request template", e);
			}
		}
	}

	@Override
	public boolean authorize(Session session, Operation operation, Resource resource)
	{
		/*
		 * TODO: implement and check decision cache before evaluating ACL and/or calling PDP
		 */

		final boolean simpleAclAuthorized = super.authorize(session, operation, resource);

		/*
		 * TODO: define combining algorithm for combining simple ACLs with XACML eval. For now, we do deny unless permit, which is the easiest to implement because it takes into account the
		 * isSuperUser() and isEmptyAclAndAuthorized()
		 */
		if (simpleAclAuthorized || this.pdpClient == null)
		{
			return simpleAclAuthorized;
		}
		/*
		 * Denied by ACL and pdpClient != null. Is it denied by PDP?
		 */
		LOGGER.debug("Authorization denied by SimpleAclAuthorizer. Trying XACML evaluation...");
		final Map<String, Object> root = ImmutableMap.of("clientHost", session.clientAddress(), "principal", session.principal(), "operation", operation.toJava(), "resourceType",
		        resource.resourceType().toJava(), "resourceName", resource.name());
		final StringWriter out = new StringWriter();
		try
		{
			xacmlReqTmpl.process(root, out);
		}
		catch (final Exception e)
		{
			LOGGER.error("Error generating XACML request from template with variables: {} -> DENY by default", root, e);
			return false;
		}

		final String xacmlReq = out.toString();
		LOGGER.debug("Calling PDP with client = {}, XACML request: {}", this.pdpClient, xacmlReq);
		final JSONObject jsonRequest = new JSONObject(xacmlReq);
		final JSONObject jsonResponse = pdpClient.post(jsonRequest, JSONObject.class);
		Xacml3JsonUtils.RESPONSE_SCHEMA.validate(jsonResponse);
		final String decision = jsonResponse.getJSONArray("Response").getJSONObject(0).getString("Decision");
		return decision.equals("Permit");
	}

}
