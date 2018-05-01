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
import java.util.Map;
import java.util.Set;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ow2.authzforce.kafka.pep.CombinedXacmlAclAuthorizer;
import org.ow2.authzforce.rest.pdp.cxf.springboot.CxfJaxrsPdpSpringBootApp;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.salesforce.kafka.test.junit4.SharedZookeeperTestResource;

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
@RunWith(SpringRunner.class)
@SpringBootTest(classes = CxfJaxrsPdpSpringBootApp.class, webEnvironment = WebEnvironment.RANDOM_PORT)
public class CombinedXacmlAclAutorizerTest
{
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

	@LocalServerPort
	private int port;

	private final CombinedXacmlAclAuthorizer authorizer;
	private final Set<InetAddress> principalHostnames;
	private final String resourceName;
	private final Set<Resource> resources;
	// private final Resource transactionalId1Resource;

	public CombinedXacmlAclAutorizerTest() throws UnknownHostException
	{
		authorizer = new CombinedXacmlAclAuthorizer();
		principalHostnames = ImmutableSet.of(InetAddress.getByAddress("host1", new byte[] { 1, 2, 3, 4 }), InetAddress.getByAddress("host2", new byte[] { 2, 3, 4, 5 }));
		resourceName = Resource$.MODULE$.ClusterResourceName();
		final Resource clusterResource = new Resource(ResourceType$.MODULE$.fromJava(ResourceType.CLUSTER), resourceName);
		final Resource topic1Resource = new Resource(ResourceType$.MODULE$.fromJava(ResourceType.TOPIC), "topic1");
		final Resource group1Resource = new Resource(ResourceType$.MODULE$.fromJava(ResourceType.GROUP), "group1");
		// transactionalId1Resource = new Resource(ResourceType$.MODULE$.fromJava(ResourceType.TRANSACTIONAL_ID), "transactional.id");
		this.resources = ImmutableSet.of(clusterResource, topic1Resource, group1Resource);
	}

	@Before
	public void setUp() throws IOException
	{
		authorizer.configure(ImmutableMap.of(KafkaConfig.ZkConnectProp(), SHARED_ZOOKEEPER_TEST_RESOURCE.getZookeeperConnectString(), CombinedXacmlAclAuthorizer.XACML_PDP_URL_CFG_PROPERTY_NAME,
		        "http://localhost:" + port + "/services/pdp" /* "http://localhost:8080/authzforce-ce/domains/A0bdIbmGEeWhFwcKrC9gSQ/pdp" */,
		        CombinedXacmlAclAuthorizer.XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME, XACML_REQ_TMPL_LOCATION));
	}

	private void testAuthorization(String username, boolean expectedAuthorized)
	{
		final KafkaPrincipal admin = new KafkaPrincipal(KafkaPrincipal.USER_TYPE, username);
		principalHostnames.forEach(hostname -> {
			final RequestChannel.Session session = new RequestChannel.Session(admin, hostname);
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
		testAuthorization("admin", true);
	}

	@Test
	public void testSubAdmin()
	{
		testAuthorization("subadmin", false);
	}
}
