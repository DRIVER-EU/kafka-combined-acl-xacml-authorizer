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
package org.ow2.authzforce.kafka.pep

import java.lang.{ Boolean => JBoolean }
import java.io.{ FileNotFoundException => JFileNotFoundException, IOException => JIOException,
    StringReader => JStringReader, StringWriter => JStringWriter }
import java.nio.file.{ Files => JFiles, Path => JPath }
import java.util.{ Collections => JCollections, Map => JMap }
//import java.util
import java.util.concurrent.{ Callable => JCallable, ExecutionException => JExecutionException }
import java.util.stream.{ Collectors => JCollectors }

import org.apache.cxf.ext.logging.{ LoggingFeature => JLoggingFeature }
import org.apache.cxf.feature.{ Feature => JFeature }
import org.apache.cxf.jaxrs.client.{ WebClient => JWebClient }
import org.json.JSONObject
import org.ow2.authzforce.jaxrs.util.JsonRiJaxrsProvider
import org.ow2.authzforce.xacml.json.model.LimitsCheckingJSONObject
import org.ow2.authzforce.xacml.json.model.XacmlJsonUtils
import org.slf4j.{ Logger, LoggerFactory }
import org.springframework.util.ResourceUtils

import com.google.common.cache.{ Cache, CacheBuilder }
import com.google.common.collect.ImmutableMap

import freemarker.cache.StringTemplateLoader
import freemarker.template.{ Configuration, Template, TemplateExceptionHandler }
import kafka.network.RequestChannel.Session
import kafka.security.auth.{ Authorizer, Operation, Resource, SimpleAclAuthorizer }
import scala.collection.JavaConverters._

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
 object CombinedXacmlAclAuthorizer {

 	private val XACML_JSON_MEDIA_TYPE = "application/xacml+json"

 	/**
 	 * Name of Kafka configuration property specifying the RESTful XACML PDP resource's URL (e.g. https://services.example.com/pdp), as defined by REST Profile of XACML, §2.2.2
 	 */
 	val XACML_PDP_URL_CFG_PROPERTY_NAME = "org.ow2.authzforce.kafka.pep.xacml.pdp.url"

 	/**
 	 * Name of Kafka configuration property specifying the location to XACML Request template file. The location must be a URL resolvable by {@link ResourceUtils}.
 	 */
 	val XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME = "org.ow2.authzforce.kafka.pep.xacml.req.tmpl.location"

 	/**
 	 * Name of Kafka configuration property specifying the maximum number of authorization cache elements in memory. Cache is disabled iff the property value is undefined or not strictly positive.
 	 */
 	val AUTHZ_CACHE_SIZE_MAX = "org.ow2.authzforce.kafka.pep.authz.cache.size.max"

 	/**
 	 * Name of Kafka configuration property specifying the location (URL supported by Spring {@link org.springframework.util.ResourceUtils}) of the HTTP client configuration as defined by
 	 * <a href="https://cxf.apache.org/docs/client-http-transport-including-ssl-support.html#ClientHTTPTransport(includingSSLsupport)-UsingConfiguration">Apache CXF format</a>, required for SSL
 	 * settings
 	 */
 	val HTTP_CLIENT_CFG_LOCATION = "org.ow2.authzforce.kafka.pep.http.client.cfg.location"

 	val MAX_JSON_STRING_LENGTH = 1000

	/*
	 * Max number of child elements - key-value pairs or items - in JSONObject/JSONArray
	 */
	val MAX_JSON_CHILDREN_COUNT = 1000

	val MAX_JSON_DEPTH = 10

  val LOGGER: Logger = LoggerFactory.getLogger("org.ow2.authzforce.kafka.pep.CombinedXacmlAclAuthorizer")
 }

class CombinedXacmlAclAuthorizer extends SimpleAclAuthorizer
{
  val LOGGER = CombinedXacmlAclAuthorizer.LOGGER

	private var pdpClientOpt:         Option[JWebClient]             = None
	private var xacmlReqTmplOpt:      Option[Template]               = None

  private var authzCacheOpt: Option[ Cache[ JMap[String, Object], JBoolean ] ] = None

  implicit class ThrowableMap( scalaAuthorizerProperties: Map[String,_] ) {

    def controlledGetPropertyByName( propertyName: String ) : Option[String] = {

  		scalaAuthorizerProperties.get(propertyName).
  			map( propertyAsString =>
  				try {
  					Some(propertyAsString.asInstanceOf[String])
  				}
  				catch {
  					case _ : ClassCastException =>
  						throw new IllegalArgumentException(this + ": authorizer configuration property '" + propertyName + "' is not a String")
            case e : Exception =>
  						throw new IllegalArgumentException(this + ": authorizer configuration property '" + propertyName + "' decoding triggered unexpected exception", e )
  				}
  			).getOrElse( {
  				LOGGER.info( s"Configuration property '${propertyName}' undefined -> XACML evaluation disabled, KAFKA ACL enabled only." )
  				None
		    } ) }
	}


	override def configure( javaAuthorizerProperties: JMap[String, _] ) {

		classOf[CombinedXacmlAclAuthorizer].synchronized {

      LOGGER.debug( s"CombinedXacmlAclAuthorizer.configure() => calling super")

			super.configure(javaAuthorizerProperties)

      LOGGER.debug( s"CombinedXacmlAclAuthorizer.configure paramters : ")

      val scalaAuthorizerProperties = javaAuthorizerProperties.asScala.toMap

      for( (k,v) <- scalaAuthorizerProperties ) {
        if( v == null ) {
          LOGGER.error( s"scalaAuthorizerProperties[${k}] is null" )
        } else {
          LOGGER.debug( s"scalaAuthorizerProperties[${k}] = ${v}" )
        }
      }

			for(
        xacmlPdpUrlStr           <- scalaAuthorizerProperties.controlledGetPropertyByName( CombinedXacmlAclAuthorizer.XACML_PDP_URL_CFG_PROPERTY_NAME                   ) ;
				cxfHttpClientCfgLocation <- scalaAuthorizerProperties.controlledGetPropertyByName( CombinedXacmlAclAuthorizer.HTTP_CLIENT_CFG_LOCATION                          ) ;
				xacmlReqTmplFileLocation <- scalaAuthorizerProperties.controlledGetPropertyByName( CombinedXacmlAclAuthorizer.XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME )
			) {

				LOGGER.debug( s"XACML PDP URL set from authorizer configuration property '${CombinedXacmlAclAuthorizer.XACML_PDP_URL_CFG_PROPERTY_NAME}': ${xacmlPdpUrlStr}")
				LOGGER.debug( s"Location of HTTP client configuration (Apache CXF format) set from authorizer configuration property '${CombinedXacmlAclAuthorizer.HTTP_CLIENT_CFG_LOCATION}': ${cxfHttpClientCfgLocation}")
//        LOGGER.info(  s"Configuration property '${CombinedXacmlAclAuthorizer.XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME}' undefined -> using default CXF HTTP client configuration")
        LOGGER.info(  s"Using CXF HTTP client configuration defined at ${xacmlReqTmplFileLocation}")

				pdpClientOpt = Some ( JWebClient
				        .create(xacmlPdpUrlStr, JCollections.singletonList(new JsonRiJaxrsProvider(/* extra parameters */)),
				                if( LOGGER.isDebugEnabled() ) {
													JCollections.singletonList(new JLoggingFeature())
												} else {
													JCollections.emptyList()
												}, cxfHttpClientCfgLocation )
				        .`type`(CombinedXacmlAclAuthorizer.XACML_JSON_MEDIA_TYPE)
								.accept(CombinedXacmlAclAuthorizer.XACML_JSON_MEDIA_TYPE)
							)

				val xacmlReqTmplFile: JPath = try {
					ResourceUtils.getFile(xacmlReqTmplFileLocation).toPath()
				}
				catch
				{
					case e: JFileNotFoundException =>
						throw new IllegalArgumentException(
						        s"XACML JSON Request template file not found at location ('${CombinedXacmlAclAuthorizer.XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME}'=) '${xacmlReqTmplFileLocation}'", e)
				}

				LOGGER.debug( s"Loading XACML Request template from file (based on authorizer configuration property '${CombinedXacmlAclAuthorizer.XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME}'): ${xacmlReqTmplFile}" )

				val xacmlReqTmplStr : String = try {
					JFiles.lines(xacmlReqTmplFile).collect(JCollectors.joining())
				}
				catch
				{
					case e: JIOException =>
						throw new RuntimeException(
						        s"Error opening XACML JSON Request template file at location ('${CombinedXacmlAclAuthorizer.XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME}'=) '${xacmlReqTmplFileLocation}'", e)
				}

        LOGGER.debug( xacmlReqTmplStr )

				val jsonRequest: JSONObject = new LimitsCheckingJSONObject(new JStringReader(xacmlReqTmplStr), CombinedXacmlAclAuthorizer.MAX_JSON_STRING_LENGTH, CombinedXacmlAclAuthorizer.MAX_JSON_CHILDREN_COUNT, CombinedXacmlAclAuthorizer.MAX_JSON_DEPTH)
				if (!jsonRequest.has("Request"))
				{
					throw new IllegalArgumentException( s"Invalid XACML JSON Request template file at location ('${CombinedXacmlAclAuthorizer.XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME}'=) '${xacmlReqTmplFile}': root key is not 'Request' as expected.")
				}

				XacmlJsonUtils.REQUEST_SCHEMA.validate(jsonRequest)

				// Create your Configuration instance, and specify if up to what FreeMarker
				// version (here 2.3.27) do you want to apply the fixes that are not 100%
				// backward-compatible. See the Configuration JavaDoc for details.
				val xacmlReqTmplEngineCfg = new Configuration(Configuration.VERSION_2_3_23)
				// Set the preferred charset template files are stored in. UTF-8 is
				// a good choice in most applications:
				xacmlReqTmplEngineCfg.setDefaultEncoding("UTF-8")

				// Sets how errors will appear.
				// During web page *development* TemplateExceptionHandler.HTML_DEBUG_HANDLER is
				// better.
				xacmlReqTmplEngineCfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER)

				// Don't log exceptions inside FreeMarker that it will thrown at you anyway:
				// XACML_REQ_TMPL_ENGINE_CFG.setLogTemplateExceptions(false);

				// Wrap unchecked exceptions thrown during template processing into
				// TemplateException-s.
				// FREEMARKER_CFG.setWrapUncheckedExceptions(true);

				val xacmlReqTmplLoader = new StringTemplateLoader()
				xacmlReqTmplLoader.putTemplate(this.toString(), xacmlReqTmplStr)
				xacmlReqTmplEngineCfg.setTemplateLoader(xacmlReqTmplLoader)

				xacmlReqTmplOpt = try {

					Some(xacmlReqTmplEngineCfg.getTemplate(this.toString()))
				}
				catch
				{
					case e: JIOException =>
						throw new RuntimeException("Error getting XACML request template", e)
				}

        val pdpRespCacheMaxSize = scalaAuthorizerProperties.controlledGetPropertyByName( CombinedXacmlAclAuthorizer.AUTHZ_CACHE_SIZE_MAX ).getOrElse("-1").toLong
        LOGGER.debug( s"Configuration property '${CombinedXacmlAclAuthorizer.AUTHZ_CACHE_SIZE_MAX}' = ${pdpRespCacheMaxSize}" )

				if (pdpRespCacheMaxSize <= 0)
				{
					LOGGER.warn( "PDP response authorization cache disabled" )

          authzCacheOpt = None
				}
				else
				{
					LOGGER.debug( s"PDP response authorization cache size set to ${pdpRespCacheMaxSize}" )

					val cacheBuilder = CacheBuilder.newBuilder().maximumSize(pdpRespCacheMaxSize)
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
          authzCacheOpt = Some( cacheBuilder.build[JMap[String,Object], JBoolean] )
				}
			}
		}
	}

	private def evalAuthzDecision( session: Session , operation: Operation , resource: Resource, authzAttributes: JMap[String, Object] ) : Boolean = {

		LOGGER.debug( s"Calling SimpleAclAuthorizer: session=${session}, operation=${operation}, resource=${resource}" )

		val simpleAclAuthorized = super.authorize(session, operation, resource)
    LOGGER.debug( s"Authorization by SimpleAclAuthorizer =${simpleAclAuthorized}" )

		/*
		 * We do deny-unless-permit combining between ACL and XACML evaluation, which is the easiest to implement because it takes into account the isSuperUser() and isEmptyAclAndAuthorized().
		 */

		if( simpleAclAuthorized ) {
      simpleAclAuthorized
    } else {

      var xacmlPdpAuthorized: Boolean = ( for(
          pdpClient    <- pdpClientOpt;
          xacmlReqTmpl <- xacmlReqTmplOpt
        ) yield {
				/*
					* Denied by ACL and pdpClient exists. Is it denied by XACML PDP?
		 		 */
		 		LOGGER.debug( s"Authorization denied by SimpleAclAuthorizer. Trying XACML PDP with request attributes=${authzAttributes}" )

		 		var out = new JStringWriter()

		 		try
		 		{
          xacmlReqTmpl.process(authzAttributes, out)

					val xacmlReq = out.toString()
			 		val jsonRequest = new JSONObject(xacmlReq)

					try
			 		{
						val jsonResponse = pdpClient.post(jsonRequest, classOf[JSONObject])
						XacmlJsonUtils.RESPONSE_SCHEMA.validate(jsonResponse)
				 		val decision = jsonResponse.getJSONArray("Response").getJSONObject(0).getString("Decision")

						LOGGER.debug("XACML PDP Decision={}", decision)

				 		decision == "Permit"

			 		} catch {

			 			case e: Exception =>
			 				LOGGER.error( s"Exception during access to Decision: ${authzAttributes} -> DENY by default", e)
			 				false
			 		}
		 		} catch {

		 			case e: Exception =>
		 				LOGGER.error( s"Error generating XACML request from template with variables: ${authzAttributes} -> DENY by default",  e)
		 				false
		 		}
			} ).getOrElse( false ) // no pdpClient and xacmlReqTmpl defined => False

      LOGGER.debug( s"Authorization by XACML PDP =${xacmlPdpAuthorized}" )
      xacmlPdpAuthorized
    }
	}

	override def authorize( session: Session, operation: Operation, resource: Resource ) : Boolean = {
    /*
		 * TODO: implement and check decision cache before evaluating ACL and/or calling PDP
		 */
		val azAttributes : JMap[String, Object] = ImmutableMap.of(
				"clientHost"   , session.clientAddress,
				"principal"    , session.principal,
				"operation"    , operation.toJava,
				"resourceType" , resource.resourceType.toJava,
				"resourceName" , resource.name
			)

    LOGGER.debug( s"Authorizing access request: ${azAttributes.toString}" )

    val isAuthorized : JBoolean = authzCacheOpt.map(

      authzCache => {

        try
        {
          if (LOGGER.isDebugEnabled())
          {
            LOGGER.debug( s"Using authorization cache: ${authzCache.stats()}")
          }

          class MyCallable( session: Session, operation: Operation, resource: Resource, azAttributes: JMap[String,Object] ) extends JCallable[JBoolean] {
            override def call:JBoolean = {
              evalAuthzDecision(session, operation, resource, azAttributes)
            }
          }

          authzCache.get( azAttributes, new MyCallable(session, operation, resource, azAttributes) )
        }
        catch
        {
          case e: JExecutionException =>
            LOGGER.error(s"Error evaluating the authorization decision request: ${azAttributes} -> returning default Deny decision", e)
            java.lang.Boolean.FALSE
        }
      }
    ).getOrElse( evalAuthzDecision(session, operation, resource, azAttributes ) )

		LOGGER.debug( s"isAuthorized (true if Permit) = ${isAuthorized}")
		isAuthorized
	}
}
