/**
 * Copyright 2019 THALES.
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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import org.apache.cxf.ext.logging.LoggingFeature;
import org.apache.cxf.feature.Feature;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.json.JSONObject;
import org.ow2.authzforce.jaxrs.util.JsonRiJaxrsProvider;
import org.ow2.authzforce.xacml.json.model.LimitsCheckingJSONObject;
import org.ow2.authzforce.xacml.json.model.XacmlJsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.ResourceUtils;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.Maps;

import freemarker.cache.StringTemplateLoader;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateExceptionHandler;
import kafka.network.RequestChannel;
import kafka.network.RequestChannel.Session;
import kafka.security.auth.Authorizer;
import kafka.security.auth.Operation;
import kafka.security.auth.Operation$;
import kafka.security.auth.Resource;
import kafka.security.auth.ResourceType$;
import kafka.security.auth.SimpleAclAuthorizer;

/**
 * Combined ACL and XACML-based {@link Authorizer} for Apache Kafka. Gets authorization decisions from a XACML PDP's REST API - as defined by OASIS standard 'REST Profile of XACML 3.0' - iff Kafka ACL
 * (evaluated by {@link SimpleAclAuthorizer}) returns Deny. To enable XACML authorization, you need to set two extra configuration properties:
 * <ul>
 * <li>{@value #XACML_PDP_URL_CFG_PROPERTY_NAME}: XACML PDP resource's URL, as defined by <a href="http://docs.oasis-open.org/xacml/xacml-rest/v1.0/xacml-rest-v1.0.html">REST Profile of XACML 3.0</a>,
 * §2.2.2, e.g. {@code https://serverhostname/services/pdp}</li>
 * <li>{@value #XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME}: location of a file that contains a <a href="https://freemarker.apache.org/">Freemarker</a> template of XACML Request formatted
 * according to <a href="http://docs.oasis-open.org/xacml/xacml-json-http/v1.0/xacml-json-http-v1.0.html">JSON Profile of XACML 3.0</a>, in which you can use
 * <a href="https://freemarker.apache.org/docs/dgui_template_exp.html">Freemarker expressions</a>, enclosed between <code>${</code> and <code>}</code>, and have access to the following
 * <a href="https://freemarker.apache.org/docs/dgui_template_exp.html#dgui_template_exp_var_toplevel">top-level variables</a> from Kafka's authorization context:
 * <ul>
 * <li><code>clientHost</code> ({@link java.net.InetAddress}): client/user host name or IP address</li>
 * <li><code>principal</code> ({@link org.apache.kafka.common.security.auth.KafkaPrincipal}): user principal</li>
 * <li><code>operation</code> ({@link org.apache.kafka.common.acl.AclOperation}): operation</li>
 * <li><code>resourceType</code> ({@link org.apache.kafka.common.resource.ResourceType}): resource type</li>
 * <li><code>resourceName</code> ({@link String}): resource name</li>
 * </ul>
 * </li>
 * <li>{@value #AUTHZ_CACHE_SIZE_MAX}: maximum number of authorization decisions cached in memory. Cache is disabled iff the property value is undefined or not strictly positive.</li>
 * <li>{@value #HTTP_CLIENT_CFG_LOCATION}: location (URL supported by Spring {@link org.springframework.util.ResourceUtils}) of the HTTP client configuration as defined by
 * <a href="https://cxf.apache.org/docs/client-http-transport-including-ssl-support.html#ClientHTTPTransport(includingSSLsupport)-UsingConfiguration">Apache CXF format</a>, required for SSL
 * settings</li>
 * </ul>
 */
public class CombinedXacmlAclAuthorizer extends SimpleAclAuthorizer
{
	private static final Logger LOGGER = LoggerFactory.getLogger(CombinedXacmlAclAuthorizer.class);

	private static final String XACML_JSON_MEDIA_TYPE = "application/xacml+json";

	/**
	 * Name of Kafka configuration property specifying the RESTful XACML PDP resource's URL (e.g. https://services.example.com/pdp), as defined by REST Profile of XACML, §2.2.2
	 */
	public static final String XACML_PDP_URL_CFG_PROPERTY_NAME = "org.ow2.authzforce.kafka.pep.xacml.pdp.url";

	/**
	 * Name of Kafka configuration property specifying the location to XACML Request template file. The location must be a URL resolvable by {@link ResourceUtils}.
	 */
	public static final String XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME = "org.ow2.authzforce.kafka.pep.xacml.req.tmpl.location";

	/**
	 * Name of Kafka configuration property specifying the maximum number of authorization cache elements in memory. Cache is disabled iff the property value is undefined or not strictly positive.
	 */
	public static final String AUTHZ_CACHE_SIZE_MAX = "org.ow2.authzforce.kafka.pep.authz.cache.size.max";

	/**
	 * Name of Kafka configuration property specifying the location (URL supported by Spring {@link org.springframework.util.ResourceUtils}) of the HTTP client configuration as defined by
	 * <a href="https://cxf.apache.org/docs/client-http-transport-including-ssl-support.html#ClientHTTPTransport(includingSSLsupport)-UsingConfiguration">Apache CXF format</a>, required for SSL
	 * settings
	 */
	public static final String HTTP_CLIENT_CFG_LOCATION = "org.ow2.authzforce.kafka.pep.http.client.cfg.location";

	private static final int MAX_JSON_STRING_LENGTH = 1000;

	private interface AuthzDecisionEvaluator
	{
		boolean eval(final Session session, final Operation operation, final Resource resource);
	}

	/*
	 * Max number of child elements - key-value pairs or items - in JSONObject/JSONArray
	 */
	private static final int MAX_JSON_CHILDREN_COUNT = 1000;

	private static final int MAX_JSON_DEPTH = 10;

	private static final String KAFKA_ANONYMOUS_USER_NAME = KafkaPrincipal.ANONYMOUS.getName();

	private WebClient pdpClient = null;

	private Template xacmlReqTmpl = null;

	private AuthzDecisionEvaluator decisionEvaluator = null;

	private final Map<String, String> consumerGroupMemberships = new ConcurrentHashMap<>();

	@Override
	public void configure(final Map<String, ?> authorizerProperties)
	{
		synchronized (CombinedXacmlAclAuthorizer.class)
		{
			super.configure(authorizerProperties);

			final Object xacmlPdpUrlObj = authorizerProperties.get(XACML_PDP_URL_CFG_PROPERTY_NAME);
			if (xacmlPdpUrlObj == null)
			{
				LOGGER.info("Configuration property '{}' undefined -> XACML evaluation disabled, KAFKA ACL enabled only.", XACML_PDP_URL_CFG_PROPERTY_NAME);
				return;
			}

			if (!(xacmlPdpUrlObj instanceof String))
			{
				throw new IllegalArgumentException(this + ": authorizer configuration property '" + XACML_PDP_URL_CFG_PROPERTY_NAME + "' is not a String");
			}

			final String xacmlPdpUrlStr = (String) xacmlPdpUrlObj;
			LOGGER.debug("XACML PDP URL set from authorizer configuration property '{}': {}", XACML_PDP_URL_CFG_PROPERTY_NAME, xacmlPdpUrlStr);

			final Object cxfHttpClientCfgLocationObj = authorizerProperties.get(HTTP_CLIENT_CFG_LOCATION);
			final String cxfHttpClientCfgLocation;
			if (cxfHttpClientCfgLocationObj == null)
			{
				LOGGER.info("Configuration property '{}' undefined -> using default Apache CXF HTTP client configuration", HTTP_CLIENT_CFG_LOCATION);
				/*
				 * When the CXF client config location is null, CXF uses some default configuration
				 */
				cxfHttpClientCfgLocation = null;
			}
			else
			{
				if (!(cxfHttpClientCfgLocationObj instanceof String))
				{
					throw new IllegalArgumentException(this + ": authorizer configuration property '" + HTTP_CLIENT_CFG_LOCATION + "' is not a String");
				}

				cxfHttpClientCfgLocation = (String) cxfHttpClientCfgLocationObj;
			}

			LOGGER.debug("Location of HTTP client configuration (Apache CXF format) set from authorizer configuration property '{}': {} (default CXF configuration if null)", HTTP_CLIENT_CFG_LOCATION,
			        cxfHttpClientCfgLocation);

			/*
			 * cxfHttpClientCfgLocation may be null -> default CXF configuration
			 */
			pdpClient = WebClient
			        .create(xacmlPdpUrlStr, Collections.singletonList(new JsonRiJaxrsProvider(/* extra parameters */)),
			                LOGGER.isDebugEnabled() ? Collections.singletonList(new LoggingFeature()) : Collections.<Feature>emptyList(), cxfHttpClientCfgLocation)
			        .type(XACML_JSON_MEDIA_TYPE).accept(XACML_JSON_MEDIA_TYPE);

			final Object xacmlReqTmplObj = authorizerProperties.get(XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME);
			if (!(xacmlReqTmplObj instanceof String))
			{
				throw new IllegalArgumentException(this + ": authorizer configuration property '" + XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME + "' is missing or not a String");
			}

			final String xacmlReqTmplFileLocation = (String) xacmlReqTmplObj;

			final Path xacmlReqTmplFile;
			try
			{
				xacmlReqTmplFile = ResourceUtils.getFile(xacmlReqTmplFileLocation).toPath();
			}
			catch (final FileNotFoundException e)
			{
				throw new IllegalArgumentException(
				        "XACML JSON Request template file not found at location ('" + XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME + "'=) '" + xacmlReqTmplFileLocation + "'", e);
			}

			LOGGER.debug("Loading XACML Request template from file (based on authorizer configuration property '{}'): {}", XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME, xacmlReqTmplFile);

			final String xacmlReqTmplStr;
			try
			{
				xacmlReqTmplStr = Files.lines(xacmlReqTmplFile).collect(Collectors.joining());
			}
			catch (final IOException e)
			{
				throw new RuntimeException(
				        "Error opening XACML JSON Request template file at location ('" + XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME + "'=) '" + xacmlReqTmplFileLocation + "'", e);
			}

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

			/*
			 * Validate the Freemarker template
			 */
			final KafkaPrincipal principal = new KafkaPrincipal(KafkaPrincipal.USER_TYPE, "alice");
			final RequestChannel.Session testSession = new RequestChannel.Session(principal, InetAddress.getLoopbackAddress());
			final Resource testResource = new Resource(ResourceType$.MODULE$.fromJava(ResourceType.TOPIC), "topic1", PatternType.LITERAL);
			final Operation testOp = Operation$.MODULE$.fromJava(AclOperation.READ);
			final Map<String, Object> testTmplVars = getTmplParams(testSession, testOp, testResource);
			LOGGER.debug("Authorization denied by SimpleAclAuthorizer. Trying XACML PDP with request attributes={}", testTmplVars);

			final StringWriter out = new StringWriter();
			try
			{
				xacmlReqTmpl.process(testTmplVars, out);
			}
			catch (final Exception e)
			{
				throw new IllegalArgumentException("Invalid XACML JSON Request template file at location ('" + XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME + "'=) '" + xacmlReqTmplFile
				        + "': Error generating XACML request from template with test variables: " + testTmplVars, e);
			}

			final String xacmlReq = out.toString();

			final JSONObject jsonRequest = new LimitsCheckingJSONObject(new StringReader(xacmlReq), MAX_JSON_STRING_LENGTH, MAX_JSON_CHILDREN_COUNT, MAX_JSON_DEPTH);
			if (!jsonRequest.has("Request"))
			{
				throw new IllegalArgumentException("Invalid XACML JSON Request template file at location ('" + XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME + "'=) '" + xacmlReqTmplFile
				        + "': root key is not 'Request' as expected.");
			}

			XacmlJsonUtils.REQUEST_SCHEMA.validate(jsonRequest);

			/*
			 * PDP client cache configuration
			 */
			final Object pdpRespCacheMaxSizeObj = authorizerProperties.get(AUTHZ_CACHE_SIZE_MAX);
			final long pdpRespCacheMaxSize = pdpRespCacheMaxSizeObj == null ? -1 : Long.valueOf((String) pdpRespCacheMaxSizeObj, 10);
			if (pdpRespCacheMaxSize <= 0)
			{
				LOGGER.warn("Configuration property '{}' undefined or value <=0 -> authorization cache disabled", AUTHZ_CACHE_SIZE_MAX);
				this.decisionEvaluator = (session, operation, resource) -> evalAuthzDecision(session, operation, resource, Optional.empty());
			}
			else
			{
				LOGGER.debug("Configuration property '{}' = {}", AUTHZ_CACHE_SIZE_MAX, pdpRespCacheMaxSize);
				final CacheBuilder<Object, Object> cacheBuilder = CacheBuilder.newBuilder().maximumSize(pdpRespCacheMaxSize);
				// if (TTIsec > 0)
				// {
				// cacheBuilder.expireAfterAccess(TTIsec, TimeUnit.SECONDS);
				// }
				//
				// if (TTLsec > 0)
				// {
				// cacheBuilder.expireAfterWrite(TTLsec, TimeUnit.SECONDS);
				// }

				/*
				 * Cannot set memory store eviction policy (applied when max size reached), because Guava cache only supports LRU
				 */
				final Cache<Map<String, Object>, Boolean> authzCache = cacheBuilder.build();
				this.decisionEvaluator = (session, operation, resource) -> {

					final Map<String, Object> azAttributes = getTmplParams(session, operation, resource);
					try
					{
						if (LOGGER.isDebugEnabled())
						{
							LOGGER.debug("Using authorization cache: {}", authzCache.stats());
						}

						return authzCache.get(azAttributes, () -> evalAuthzDecision(session, operation, resource, Optional.of(azAttributes)));
					}
					catch (final ExecutionException e)
					{
						LOGGER.error("Error evaluating the authorization decision request: {} -> returning default Deny decision", azAttributes, e);
						return false;
					}
				};
			}

		}
	}

	private static enum KAFKA_API_OPERATION
	{
		JOIN_GROUP, UNDEFINED;
	}

	private static String KAFKA_API_OPERATION_KEY = "kafka.api.operation";

	private Map<String, Object> getTmplParams(final Session session, final Operation operation, final Resource resource)
	{
		final ResourceType jResourceType = resource.resourceType().toJava();
		final AclOperation jAclOp = operation.toJava();
		final KafkaPrincipal principal = session.principal();
		final String principalName = principal.getName();

		final KAFKA_API_OPERATION kafkaApiOp;
		final String consumerGroupId;
		if (principal.getPrincipalType().equals(KafkaPrincipal.USER_TYPE) && !principalName.equals(KAFKA_ANONYMOUS_USER_NAME))
		{
			/*
			 * Join group
			 */
			if (jResourceType == ResourceType.GROUP && jAclOp == AclOperation.READ)
			{
				kafkaApiOp = KAFKA_API_OPERATION.JOIN_GROUP;
				consumerGroupId = null;
			}
			else
			{
				kafkaApiOp = KAFKA_API_OPERATION.UNDEFINED;
				consumerGroupId = consumerGroupMemberships.get(principalName);
			}
		}
		else
		{
			kafkaApiOp = KAFKA_API_OPERATION.UNDEFINED;
			consumerGroupId = null;
		}

		final Map<String, Object> azAttributes = Maps.newHashMapWithExpectedSize(6);
		azAttributes.put("clientHost", session.clientAddress());
		azAttributes.put("principal", principal);
		azAttributes.put("consumerGroupId", consumerGroupId);
		azAttributes.put("operation", jAclOp);
		azAttributes.put("resourceType", jResourceType);
		azAttributes.put("resourceName", resource.name());
		azAttributes.put(KAFKA_API_OPERATION_KEY, kafkaApiOp);
		return azAttributes;
	}

	private boolean evalAuthzDecision(final Session session, final Operation operation, final Resource resource, final Optional<Map<String, Object>> azAttributes)
	{
		LOGGER.debug("Calling SimpleAclAuthorizer: session={}, operation={}, resource={}", session, operation, resource);

		final boolean simpleAclAuthorized = super.authorize(session, operation, resource);

		/*
		 * We do deny-unless-permit combining between ACL and XACML evaluation, which is the easiest to implement because it takes into account the isSuperUser() and isEmptyAclAndAuthorized().
		 */
		if (simpleAclAuthorized || this.pdpClient == null)
		{
			return simpleAclAuthorized;
		}
		/*
		 * Denied by ACL and pdpClient != null. Is it denied by XACML PDP?
		 */

		final Map<String, Object> authzAttributes = azAttributes.orElseGet(() -> getTmplParams(session, operation, resource));
		LOGGER.debug("Authorization denied by SimpleAclAuthorizer. Trying XACML PDP with request attributes={}", authzAttributes);

		final StringWriter out = new StringWriter();
		try
		{
			xacmlReqTmpl.process(authzAttributes, out);
		}
		catch (final Exception e)
		{
			LOGGER.error("Error generating XACML request from template with variables: {} -> DENY by default", authzAttributes, e);
			return false;
		}

		final String xacmlReq = out.toString();
		final JSONObject jsonRequest = new JSONObject(xacmlReq);

		/*
		 * FIXME: handle potential exception
		 */
		final JSONObject jsonResponse = pdpClient.post(jsonRequest, JSONObject.class);

		/*
		 * FIXME: handle potential exception
		 */
		XacmlJsonUtils.RESPONSE_SCHEMA.validate(jsonResponse);

		final String decision = jsonResponse.getJSONArray("Response").getJSONObject(0).getString("Decision");
		final boolean isAuthorized = decision.equals("Permit");

		/**
		 * Handle group memberships (JoinGroup, LeaveGroup) and group-based permissions
		 * <p>
		 * TODO: how to differentiate JOIN from LEAVE? For the moment, consumer is considered having left a group only when joining another one (group overriden in consumerGroupMemberships map)
		 */
		if (isAuthorized && authzAttributes.get(KAFKA_API_OPERATION_KEY) == KAFKA_API_OPERATION.JOIN_GROUP)
		{
			/*
			 * Join group
			 */
			consumerGroupMemberships.put(session.principal().getName(), resource.name());
		}

		return isAuthorized;
	}

	@Override
	public boolean authorize(final Session session, final Operation operation, final Resource resource)
	{
		// System.out.println(String.format("authorize( session=[%s], operation= [%s], resource.type=[%s], resource.name=[%s], resource.patternType=[%s] )", session, operation.toJava(),
		// resource.resourceType().toJava(), resource.name(), resource.patternType()));
		LOGGER.debug("authorize( session=[{}], operation= [{}], resource=[{}] )", session, operation, resource);

		final boolean isAuthorized = this.decisionEvaluator.eval(session, operation, resource);
		LOGGER.debug("isAuthorized (true iff Permit) = {}", isAuthorized);

		return isAuthorized;
	}

	// public static void main(final String... args)
	// {
	// System.out.println(org.apache.kafka.common.resource.ResourceType.TOPIC);
	// }

}
