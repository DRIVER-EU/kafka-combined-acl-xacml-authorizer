# XACML-enabled Authorizer for Apache Kafka

## Terms
* **[XACML](http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html)**: eXtensisble Access Control Markup Language for access policies and access requests/responses, standardized by OASIS.
* **PDP**: Policy Decision Point, as defined in XACML standard.
* **PAP**: Policy Administration Point, as defined in XACML standard.

## Project description
This project provides an [Authorizer](https://kafka.apache.org/documentation/#security_authz) implementation for Apache Kafka that extends the Kafa's default authorizer (`kafka.security.auth.SimpleAclAuthorizer`) to enable getting XACML authorization decisions from a XACML-enabled PDP's REST API as well, according to the [REST Profile of XACML 3.0](http://docs.oasis-open.org/xacml/xacml-rest/v1.0/xacml-rest-v1.0.html). [AuthzForce Server](https://github.com/authzforce/server) and [AuthzForce RESTful PDP](https://github.com/authzforce/restful-pdp) both provide such REST API. Usually, the latter is enough for simple use cases, unless you need a PAP API, multi-tenancy, etc. in which case AuthzForce Server is a better fit (see the [documentation for the full list of features](http://authzforce-ce-fiware.readthedocs.io/en/latest/Features.html))

In other terms, you can still use [Kafka ACLs](http://kafka.apache.org/documentation.html#security_authz) with this same authorizer as you would with the default one. XACML evaluation must be enabled explicitly by setting specific properties as described later below. *XACML evaluation* here stands for the extra process of getting a XACML authorization decision from a remote PDP according to the REST Profile of XACML 3.0.

The authorizer combines Kafka ACL evaluation with XACML evaluation as follows: 

* If ACL evaluation returns Permit, return Permit.
* Else: 
  * If XACML evaluation is disabled, return Deny.
  * Else: If and only if the result of XACML evaluation is Permit, return Permit.
  
## Installation
Get the `tar.gz` distribution from the [latest release on the GitHub repository](https://github.com/DRIVER-EU/kafka-combined-acl-xacml-authorizer/releases) and extract the files to some folder, e.g. `/opt/authzforce-ce-kafka-extensions`. You should have a `lib` folder inside.

## Configuration
To enable the authorizer on Kafka, set the server's property: 

`authorizer.class.name=org.ow2.authzforce.kafka.pep.CombinedXacmlAclAuthorizer`

To enable XACML evaluation, set the extra following authorizer properties:
* **`org.ow2.authzforce.kafka.pep.xacml.pdp.url`**: XACML PDP resource's URL, as defined by [REST Profile of XACML 3.0](http://docs.oasis-open.org/xacml/xacml-rest/v1.0/xacml-rest-v1.0.html), §2.2.2, e.g. `https://serverhostname/services/pdp` for a [AuthzForce RESTful PDP](https://github.com/authzforce/restful-pdp) instance, or `https://serverhostname/authzforce-ce/domains/XXX/pdp` for a domain `XXX` on a [AuthzForce Server](https://github.com/authzforce/server) instance.
* **`org.ow2.authzforce.kafka.pep.xacml.req.tmpl`:** [Freemarker](https://freemarker.apache.org/) template of XACML Request formatted according to [JSON Profile of XACML 3.0](http://docs.oasis-open.org/xacml/xacml-json-http/v1.0/xacml-json-http-v1.0.html), in which you can use [Freemarker expressions](https://freemarker.apache.org/docs/dgui_template_exp.html), enclosed between `${` and `}`, and have access to the following [top-level variables](https://freemarker.apache.org/docs/dgui_template_exp.html#dgui_template_exp_var_toplevel) from Kafka's authorization context:

| Variable name | Variable type | Description |
| --- | --- | --- |
|`clientHost` | [java.net.InetAddress](https://docs.oracle.com/javase/8/docs/api/java/net/InetAddress.html) | client/user host name or IP address |
|`principal`| [org.apache.kafka.common.security.auth.KafkaPrincipal](https://kafka.apache.org/11/javadoc/org/apache/kafka/common/security/auth/KafkaPrincipal.html)| user principal|
|`operation`|[org.apache.kafka.common.acl.AclOperation](http://kafka.apache.org/11/javadoc/index.html?org/apache/kafka/common/acl/AclOperation.html)|operation|
|`resourceType`|[org.apache.kafka.common.resource.ResourceType](https://kafka.apache.org/11/javadoc/org/apache/kafka/common/resource/ResourceType.html)|resource type|
|`resourceName`|`String`|resource name|

For example:
 
```json
org.ow2.authzforce.kafka.pep.xacml.req.tmpl={"Request"\:{"Category"\:[{"CategoryId"\:"urn\:oasis\:names\:tc\:xacml\:1.0\:subject-category\:access-subject","Attribute"\:[{"AttributeId"\:"urn\:oasis\:names\:tc\:xacml\:1.0\:subject\:subject-id","DataType"\:"http\://www.w3.org/2001/XMLSchema#string","Value"\:"${principal.name}"},{"AttributeId"\:"urn\:oasis\:names\:tc\:xacml\:1.0\:subject\:authn-locality\:dns-name","DataType"\:"urn\:oasis\:names\:tc\:xacml\:2.0\:data-type\:dnsName","Value"\:"${clientHost.hostName}"},{"AttributeId"\:"urn\:oasis\:names\:tc\:xacml\:3.0\:subject\:authn-locality\:ip-address","DataType"\:"urn\:oasis\:names\:tc\:xacml\:2.0\:data-type\:ipAddress","Value"\:"${clientHost.hostAddress}"}]},{"CategoryId"\:"urn\:oasis\:names\:tc\:xacml\:3.0\:attribute-category\:action","Attribute"\:[{"AttributeId"\:"urn\:oasis\:names\:tc\:xacml\:1.0\:action\:action-id","DataType"\:"http\://www.w3.org/2001/XMLSchema#string","Value"\:"${operation}",}]},{"CategoryId"\:"urn\:oasis\:names\:tc\:xacml\:3.0\:attribute-category\:resource","Attribute"\:[{"AttributeId"\:"urn\:thalesgroup\:xacml\:resource\:resource-type","DataType"\:"http\://www.w3.org/2001/XMLSchema#string","Value"\:"${resourceType}"},{"AttributeId"\:"urn\:oasis\:names\:tc\:xacml\:1.0\:resource\:resource-id","DataType"\:"http\://www.w3.org/2001/XMLSchema#string","Value"\:"${resourceName}"}]},{"CategoryId"\:"urn\:oasis\:names\:tc\:xacml\:3.0\:attribute-category\:environment","Attribute"\:[{"AttributeId"\:"urn\:thalesgroup\:xacml\:environment\:deployment-environment","DataType"\:"http\://www.w3.org/2001/XMLSchema#string","Value"\:"DEV"}]}]}}
```

This example is derived from the [template in the source](src/test/resources/request.xacml.json.ftl), i.e. adapted for the Java Properties format, and should be applicable to most cases.

As shown in this example, the property value must be formatted according to [Java Properties API](https://docs.oracle.com/javase/8/docs/api/index.html?java/util/Properties.html). In particular, you must **either compact your JSON template on one line; or on multiple lines but only if you terminate each line with a backslash as mentioned on [Java Properties#load(Reader) API](https://docs.oracle.com/javase/8/docs/api/java/util/Properties.html#load-java.io.Reader-). You must also escape all ':' with backslash**, because ':' is a special character (like '=') in Java properties file format. 

## Starting Kafka
Make sure Zookeeper is started first:
```sh
~/DRIVER+/kafka_2.11-1.1.0$ bin/zookeeper-server-start.sh config/zookeeper.properties
```

Add the all JARs in the `lib` folder extracted earlier (*Installation* section) to the CLASSPATH environment variable before starting Kafka, for example:

```sh
~/DRIVER+/kafka_2.11-1.1.0$ CLASSPATH=/opt/authzforce-ce-kafka-extensions/lib/* bin/kafka-server-start.sh config/server.properties
```
