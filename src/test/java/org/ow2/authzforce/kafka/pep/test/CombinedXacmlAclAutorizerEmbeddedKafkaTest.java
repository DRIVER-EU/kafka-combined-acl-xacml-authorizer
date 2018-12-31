/**
 * Copyright 2018 THALES.
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

import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Properties;
import java.util.concurrent.ExecutionException;

import org.apache.curator.test.TestingServer;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.utils.Time;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.ow2.authzforce.kafka.pep.CombinedXacmlAclAuthorizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.junit4.rules.SpringClassRule;
import org.springframework.test.context.junit4.rules.SpringMethodRule;
import org.springframework.util.SocketUtils;

import eu.driver.testbed.sec.authz.service.AuthzWsSpringBootApp;
import kafka.admin.RackAwareMode;
import kafka.security.auth.SimpleAclAuthorizer;
import kafka.server.KafkaConfig;
import kafka.server.KafkaServerStartable;
import kafka.zk.AdminZkClient;
import kafka.zk.KafkaZkClient;
import kafka.zookeeper.ZooKeeperClient;

/**
 * @see "https://github.com/apache/kafka/blob/trunk/core/src/test/scala/integration/kafka/api/AuthorizerIntegrationTest.scala"
 * @see "https://github.com/coheigea/testcases/blob/master/apache/bigdata/kafka/src/test/java/org/apache/coheigea/bigdata/kafka/KafkaAuthorizerTest.java"
 */
@RunWith(Parameterized.class)
// @SpringBootTest(classes = AuthzWsSpringBootApp.class, webEnvironment = WebEnvironment.DEFINED_PORT)
public class CombinedXacmlAclAutorizerEmbeddedKafkaTest
{
	private static final Logger LOGGER = LoggerFactory.getLogger(CombinedXacmlAclAutorizerEmbeddedKafkaTest.class);

	/*
	 * Must match server.port in authz server's application.properies (Spring Boot)
	 */
	// private static final int AUTHZ_SERVER_PORT = 44443;

	@ClassRule
	public static final SpringClassRule SPRING_CLASS_RULE = new SpringClassRule();

	@Parameters
	public static Collection<Object[]> data()
	{
		/*
		 * Tests with cache (1000 entries max) and without (max size -1)
		 */
		return Arrays.asList(new Object[][] { { -1 }/* , { 1000 } */ });
	}

	private static final String AUTHZ_SERVICE_PORT_STRING = Integer.toString(SocketUtils.findAvailableTcpPort(), 10);

	private static ConfigurableApplicationContext AUTHZ_SERVICE_APP_CTX;

	private static TestingServer ZK_SERVER = null;

	private static final String KAFKA_SSL_PORT_STRING = Integer.toString(SocketUtils.findAvailableTcpPort(), 10);

	private static final Properties KAFKA_BROKER_PROPS_DEFAULT = new Properties();

	private static KafkaServerStartable KAFKA_SERVER = null;

	@BeforeClass
	public static void setup() throws Exception
	{
		System.setProperty("javax.xml.accessExternalSchema", "all");
		final SpringApplication app = new SpringApplication(AuthzWsSpringBootApp.class);
		app.setDefaultProperties(Collections.singletonMap("server.port", AUTHZ_SERVICE_PORT_STRING));
		AUTHZ_SERVICE_APP_CTX = app.run();

		ZK_SERVER = new TestingServer();

		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.BrokerIdProp(), "1");
		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.ZkConnectProp(), ZK_SERVER.getConnectString());
		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.ReplicaSocketTimeoutMsProp(), "1500");
		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.ControlledShutdownEnableProp(), Boolean.TRUE.toString());
		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.OffsetsTopicPartitionsProp(), "1");
		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.OffsetsTopicReplicationFactorProp(), "1");
		/*
		 * Do not set port or host.name property (DEPRECATED), set proper hostname:port in listeners property instead.
		 */
		/*
		 * Enable SSL
		 */
		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.ListenersProp(), "SSL://localhost:" + KAFKA_SSL_PORT_STRING);
		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.InterBrokerSecurityProtocolProp(), "SSL");
		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.SslTruststoreLocationProp(), "target/test-classes/truststore.jks");
		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.SslTruststorePasswordProp(), "changeit");
		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.SslKeystoreLocationProp(), "target/test-classes/kafka-server.p12");
		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.SslKeystoreTypeProp(), "pkcs12");
		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.SslKeystorePasswordProp(), "changeit");
		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.SslKeyPasswordProp(), "changeit");
		KAFKA_BROKER_PROPS_DEFAULT.put(KafkaConfig.SslClientAuthProp(), "required");
		/*
		 * ACL super users
		 */
		KAFKA_BROKER_PROPS_DEFAULT.put(SimpleAclAuthorizer.SuperUsersProp(), "User:CN=Admin Client,OU=Authz Service Dev Project,OU=WP923,O=DRIVER-PROJECT.eu");
	}

	@AfterClass
	public static void cleanup() throws Exception
	{
		if (KAFKA_SERVER != null)
		{
			KAFKA_SERVER.shutdown();
		}

		if (ZK_SERVER != null)
		{
			ZK_SERVER.stop();
		}

		/* int exitCode = */ SpringApplication.exit(AUTHZ_SERVICE_APP_CTX, () -> 0);
		// System.exit(exitCode);
	}

	@Rule
	public final SpringMethodRule springMethodRule = new SpringMethodRule();

	/*
	 * Only set after constructor called
	 */
	// @LocalServerPort
	// private int authzServicePort;

	@Autowired
	public CombinedXacmlAclAutorizerEmbeddedKafkaTest(final long authzCacheMaxSize) throws UnknownHostException
	{
		/*
		 * Broker authorizer properties
		 */
		/*
		 * Authorizer properties
		 */
		final Properties kafkaBrokerProps = new Properties();
		kafkaBrokerProps.putAll(KAFKA_BROKER_PROPS_DEFAULT);
		kafkaBrokerProps.put(KafkaConfig.AuthorizerClassNameProp(), CombinedXacmlAclAuthorizer.class.getName());
		kafkaBrokerProps.put(CombinedXacmlAclAuthorizer.XACML_REQUEST_TEMPLATE_LOCATION_CFG_PROPERTY_NAME, CombinedXacmlAclAutorizerUnitTest.XACML_REQ_TMPL_LOCATION);
		kafkaBrokerProps.put(CombinedXacmlAclAuthorizer.HTTP_CLIENT_CFG_LOCATION, "file:target/test-classes/pdp-client.xml");
		kafkaBrokerProps.put(CombinedXacmlAclAuthorizer.XACML_PDP_URL_CFG_PROPERTY_NAME, "https://localhost:" + AUTHZ_SERVICE_PORT_STRING + "/services/authz/pdp");
		kafkaBrokerProps.put(CombinedXacmlAclAuthorizer.AUTHZ_CACHE_SIZE_MAX, Long.toString(authzCacheMaxSize, 10));

		if (KAFKA_SERVER != null)
		{
			KAFKA_SERVER.awaitShutdown();
		}

		KAFKA_SERVER = KafkaServerStartable.fromProps(kafkaBrokerProps);
		KAFKA_SERVER.startup();

		/*
		 * Create some topics
		 */
		final ZooKeeperClient zkClient = new ZooKeeperClient(ZK_SERVER.getConnectString(), 5000, 5000, 5, Time.SYSTEM, "kafka.server", "SessionExpireListener");

		try (final KafkaZkClient kafkaZkClient = new KafkaZkClient(zkClient, false, Time.SYSTEM))
		{
			if (!kafkaZkClient.topicExists("SecTopic"))
			{
				final AdminZkClient adminZkClient = new AdminZkClient(kafkaZkClient);
				adminZkClient.createTopic("SecTopic", 1, 1, new Properties(), RackAwareMode.Enforced$.MODULE$);
			}
		}
	}

	private static final Properties KAFKA_PRODUCER_PROPS = new Properties();
	static
	{
		KAFKA_PRODUCER_PROPS.put(ProducerConfig.CLIENT_ID_CONFIG, "admin-ssl");
		KAFKA_PRODUCER_PROPS.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:" + KAFKA_SSL_PORT_STRING);
		KAFKA_PRODUCER_PROPS.put(ProducerConfig.ACKS_CONFIG, "all");
		KAFKA_PRODUCER_PROPS.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
		KAFKA_PRODUCER_PROPS.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
		/*
		 * SSL
		 */
		KAFKA_PRODUCER_PROPS.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SSL");
		KAFKA_PRODUCER_PROPS.put(SslConfigs.SSL_KEYSTORE_TYPE_CONFIG, "PKCS12");
		KAFKA_PRODUCER_PROPS.put(SslConfigs.SSL_KEYSTORE_LOCATION_CONFIG, "target/test-classes/admin-client.p12");
		KAFKA_PRODUCER_PROPS.put(SslConfigs.SSL_KEYSTORE_PASSWORD_CONFIG, "changeit");
		KAFKA_PRODUCER_PROPS.put(SslConfigs.SSL_KEY_PASSWORD_CONFIG, "changeit");
		KAFKA_PRODUCER_PROPS.put(SslConfigs.SSL_TRUSTSTORE_LOCATION_CONFIG, "target/test-classes/truststore.jks");
		KAFKA_PRODUCER_PROPS.put(SslConfigs.SSL_TRUSTSTORE_PASSWORD_CONFIG, "changeit");
	}

	// private static final Properties KAFKA_ADMIN_CLIENT_PROPS = new Properties();
	// static
	// {
	// KAFKA_ADMIN_CLIENT_PROPS.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:" + KAFKA_SSL_PORT_STRING);
	// KAFKA_ADMIN_CLIENT_PROPS.put(AdminClientConfig.CLIENT_ID_CONFIG, "admin-ssl");
	// // KAFKA_ADMIN_CLIENT_PROPS.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
	// // KAFKA_ADMIN_CLIENT_PROPS.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
	// KAFKA_ADMIN_CLIENT_PROPS.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SSL");
	// KAFKA_ADMIN_CLIENT_PROPS.put(SslConfigs.SSL_KEYSTORE_TYPE_CONFIG, "PKCS12");
	// KAFKA_ADMIN_CLIENT_PROPS.put(SslConfigs.SSL_KEYSTORE_LOCATION_CONFIG, "target/test-classes/admin-client.p12");
	// KAFKA_ADMIN_CLIENT_PROPS.put(SslConfigs.SSL_KEYSTORE_PASSWORD_CONFIG, "changeit");
	// KAFKA_ADMIN_CLIENT_PROPS.put(SslConfigs.SSL_KEY_PASSWORD_CONFIG, "changeit");
	// KAFKA_ADMIN_CLIENT_PROPS.put(SslConfigs.SSL_TRUSTSTORE_LOCATION_CONFIG, "target/test-classes/truststore.jks");
	// KAFKA_ADMIN_CLIENT_PROPS.put(SslConfigs.SSL_TRUSTSTORE_PASSWORD_CONFIG, "changeit");
	// }

	private static final Properties KAFKA_OTHER_CONSUMER_PROPS = new Properties();
	static
	{
		KAFKA_OTHER_CONSUMER_PROPS.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:" + KAFKA_SSL_PORT_STRING);
		KAFKA_OTHER_CONSUMER_PROPS.put(ConsumerConfig.GROUP_ID_CONFIG, "test");
		KAFKA_OTHER_CONSUMER_PROPS.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, "true");
		KAFKA_OTHER_CONSUMER_PROPS.put(ConsumerConfig.AUTO_COMMIT_INTERVAL_MS_CONFIG, "1000");
		KAFKA_OTHER_CONSUMER_PROPS.put(ConsumerConfig.SESSION_TIMEOUT_MS_CONFIG, "30000");
		KAFKA_OTHER_CONSUMER_PROPS.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
		KAFKA_OTHER_CONSUMER_PROPS.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringDeserializer");
		KAFKA_OTHER_CONSUMER_PROPS.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringDeserializer");
		/*
		 * SSL
		 */
		KAFKA_OTHER_CONSUMER_PROPS.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SSL");
		KAFKA_OTHER_CONSUMER_PROPS.put(SslConfigs.SSL_KEYSTORE_TYPE_CONFIG, "PKCS12");
		KAFKA_OTHER_CONSUMER_PROPS.put(SslConfigs.SSL_KEYSTORE_LOCATION_CONFIG, "target/test-classes/other-client.p12");
		KAFKA_OTHER_CONSUMER_PROPS.put(SslConfigs.SSL_KEYSTORE_PASSWORD_CONFIG, "changeit");
		KAFKA_OTHER_CONSUMER_PROPS.put(SslConfigs.SSL_KEY_PASSWORD_CONFIG, "changeit");
		KAFKA_OTHER_CONSUMER_PROPS.put(SslConfigs.SSL_TRUSTSTORE_LOCATION_CONFIG, "target/test-classes/truststore.jks");
		KAFKA_OTHER_CONSUMER_PROPS.put(SslConfigs.SSL_TRUSTSTORE_PASSWORD_CONFIG, "changeit");
	}

	@Test
	public void testConsumeTopicAsConsumerGroup() throws InterruptedException, ExecutionException
	{

		// Define the record we want to produce
		final ProducerRecord<String, String> producerRecord = new ProducerRecord<>("SecTopic", "Message1", "Hello!");

		try (final KafkaConsumer<String, String> consumer = new KafkaConsumer<>(KAFKA_OTHER_CONSUMER_PROPS))
		{
			consumer.subscribe(Collections.singletonList("SecTopic"));

			// Create a new producer

			try (final KafkaProducer<String, String> producer = new KafkaProducer<>(KAFKA_PRODUCER_PROPS))
			{
				producer.send(producerRecord);
				producer.flush();
				LOGGER.info("Produce completed");
			}

			ConsumerRecord<String, String> record = null;
			for (int i = 0; i < 1000; i++)
			{
				final ConsumerRecords<String, String> consumerRecords = consumer.poll(Duration.ofSeconds(10));
				final int recordCount = consumerRecords.count();
				LOGGER.info("Found {} records in kafka", recordCount);
				if (recordCount > 0)
				{
					record = consumerRecords.iterator().next();
					LOGGER.info("Found records in kafka: {}", record);
					break;
				} // else
				Thread.sleep(500);
			}

			Assert.assertNotNull(record);
			Assert.assertEquals("Hello!", record.value());
		}
	}
}
