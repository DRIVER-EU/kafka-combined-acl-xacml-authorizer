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

package org.ow2.authzforce.kafka.pep.test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.ow2.authzforce.kafka.pep.CombinedXacmlAclAuthorizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.rules.SpringClassRule;
import org.springframework.test.context.junit4.rules.SpringMethodRule;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.salesforce.kafka.test.junit4.SharedZookeeperTestResource;

import eu.driver.testbed.sec.authz.service.AuthzWsSpringBootApp;
import kafka.network.RequestChannel;
import kafka.security.auth.Operation$;
import kafka.security.auth.Resource;
import kafka.security.auth.Resource$;
import kafka.security.auth.ResourceType$;
import kafka.server.KafkaConfig;

/**
 * @see "https://github.com/apache/kafka/blob/trunk/core/src/test/scala/integration/kafka/api/AuthorizerIntegrationTest.scala"
 * @see "https://github.com/apache/sentry/blob/master/sentry-binding/sentry-binding-kafka/src/test/java/org/apache/sentry/kafka/authorizer/SentryKafkaAuthorizerTest.java"
 */
@RunWith(Parameterized.class)
@SpringBootTest(classes = AuthzWsSpringBootApp.class, webEnvironment = WebEnvironment.RANDOM_PORT)
public class CombinedXacmlAclAutorizerTest
{
	private static final Logger LOGGER = LoggerFactory.getLogger(AuthzWsSpringBootApp.class);

	private static final String XACML_REQ_TMPL_LOCATION = "classpath:request.xacml.json.ftl";

	private static final Map<ResourceType, Set<AclOperation>> OPS_BY_RESOURCE_TYPE = ImmutableMap.of(
	        //
	        ResourceType.CLUSTER, ImmutableSet.of(AclOperation.ALTER, AclOperation.CLUSTER_ACTION, AclOperation.CREATE, AclOperation.DESCRIBE, AclOperation.IDEMPOTENT_WRITE),
	        //
	        ResourceType.GROUP, ImmutableSet.of(AclOperation.READ, AclOperation.DESCRIBE, AclOperation.DELETE),
	        //
	        ResourceType.TOPIC,
	        ImmutableSet.of(AclOperation.READ, AclOperation.WRITE, AclOperation.DESCRIBE, AclOperation.ALTER, AclOperation.DELETE, AclOperation.DESCRIBE_CONFIGS, AclOperation.ALTER_CONFIGS)
	//
	// , ResourceType.TRANSACTIONAL_ID, ImmutableSet.of(AclOperation.WRITE, AclOperation.DESCRIBE)
	);

	@ClassRule
	public static final SharedZookeeperTestResource SHARED_ZOOKEEPER_TEST_RESOURCE = new SharedZookeeperTestResource();

	@ClassRule
	public static final SpringClassRule SPRING_CLASS_RULE = new SpringClassRule();

	@Parameters
	public static Collection<Object[]> data()
	{
		/*
		 * Tests with cache (1000 entries max) and without (max size -1)
		 */
		return Arrays.asList(new Object[][] { { -1 }, { 1000 } });
	}

	@Rule
	public final SpringMethodRule springMethodRule = new SpringMethodRule();

	@LocalServerPort
	private int port;

	private final CombinedXacmlAclAuthorizer authorizer;
	private final Set<InetAddress> principalHostnames;
	private final String resourceName;
	private final Set<Resource> resources;
	// private final Resource transactionalId1Resource;

	private final long authzCacheMaxSize;

	public CombinedXacmlAclAutorizerTest(final long authzCacheMaxSize) throws UnknownHostException
	{
		authorizer = new CombinedXacmlAclAuthorizer();
		principalHostnames = ImmutableSet.of(InetAddress.getByAddress("host1", new byte[] { 1, 2, 3, 4 }), InetAddress.getByAddress("host2", new byte[] { 2, 3, 4, 5 }));
		resourceName = Resource$.MODULE$.ClusterResourceName();
		final Resource clusterResource = new Resource(ResourceType$.MODULE$.fromJava(ResourceType.CLUSTER), resourceName);
		final Resource topic1Resource = new Resource(ResourceType$.MODULE$.fromJava(ResourceType.TOPIC), "topic1");
		final Resource group1Resource = new Resource(ResourceType$.MODULE$.fromJava(ResourceType.GROUP), "group1");
		// transactionalId1Resource = new Resource(ResourceType$.MODULE$.fromJava(ResourceType.TRANSACTIONAL_ID), "transactional.id");
		this.resources = ImmutableSet.of(clusterResource, topic1Resource, group1Resource);

		this.authzCacheMaxSize = authzCacheMaxSize;
	}

	@Before
	public void setUp() throws IOException
	{
		authorizer.configure(ImmutableMap.of(KafkaConfig.ZkConnectProp(), SHARED_ZOOKEEPER_TEST_RESOURCE.getZookeeperConnectString(), CombinedXacmlAclAuthorizer.XACML_PDP_URL_CFG_PROPERTY_NAME,
		        "http://localhost:" + port + "/services/authz/pdp", CombinedXacmlAclAuthorizer.XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME, XACML_REQ_TMPL_LOCATION,
		        CombinedXacmlAclAuthorizer.AUTHZ_CACHE_SIZE_MAX, Long.toString(authzCacheMaxSize, 10)));
	}

	private void testAuthorizationForAllResourcesAndOperations(final String username, final boolean expectedAuthorized)
	{
		final KafkaPrincipal principal = new KafkaPrincipal(KafkaPrincipal.USER_TYPE, username);
		principalHostnames.forEach(hostname -> {
			final RequestChannel.Session session = new RequestChannel.Session(principal, hostname);
			resources.forEach(resource -> {
				final ResourceType resourceType = resource.resourceType().toJava();
				OPS_BY_RESOURCE_TYPE.get(resourceType).forEach(op -> {
					Assert.assertEquals("Test failed.", expectedAuthorized, authorizer.authorize(session, Operation$.MODULE$.fromJava(op), resource));
				});
			});
		});
	}

	@Test
	public void testAdmin()
	{
		testAuthorizationForAllResourcesAndOperations("admin", true);
	}

	@Test
	public void testSubAdmin()
	{
		testAuthorizationForAllResourcesAndOperations("subadmin", false);
	}

	private void testAuthorization(final KafkaPrincipal principal, final AclOperation op, final ResourceType resourceType, final String resourceId, final boolean expectedAuthorized)
	{
		final RequestChannel.Session session = new RequestChannel.Session(principal, InetAddress.getLoopbackAddress());
		final Resource resource = new Resource(ResourceType$.MODULE$.fromJava(resourceType), resourceId);
		Assert.assertEquals("Test failed.", expectedAuthorized, authorizer.authorize(session, Operation$.MODULE$.fromJava(op), resource));
		if (authzCacheMaxSize > 0)
		{
			LOGGER.info("Testing authorization decision cache");
			Assert.assertEquals("Test failed.", expectedAuthorized, authorizer.authorize(session, Operation$.MODULE$.fromJava(op), resource));
		}
	}

	@Test
	public void testAnonymousReadConnectGroup()
	{
		testAuthorization(KafkaPrincipal.ANONYMOUS, AclOperation.READ, ResourceType.GROUP, "compose-connect-group", true);
	}

	@Test
	public void testAnonymousReadSchemaRegistryStoreTopic()
	{
		testAuthorization(KafkaPrincipal.ANONYMOUS, AclOperation.READ, ResourceType.TOPIC, "_schemas", true);
	}

	@Test
	public void testAnonymousReadConnectStoreTopics()
	{
		Arrays.asList("docker-connect-configs", "docker-connect-offsets", "docker-connect-status").forEach(topicId -> {
			testAuthorization(KafkaPrincipal.ANONYMOUS, AclOperation.READ, ResourceType.TOPIC, topicId, true);
		});

	}
}
