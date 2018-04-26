# RESTful XACML-enabled Authorizer for Apache Kafka

## Terms
* [XACML](http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html): eXtensisble Access Control Markup Language for access policies and access requests/responses, standardized by OASIS.
* PDP: Policy Decision Point, as defined in XACML standard.

## Project description
This project provides an [Authorizer](https://kafka.apache.org/documentation/#security_authz) implementation for Apache Kafka that extends the out-of-the-box authorizer (`kafka.security.auth.SimpleAclAuthorizer`) to enable getting XACML authorization decisions from a XACML-enabled PDP's REST API as well, according to the [REST Profile of XACML 3.0](http://docs.oasis-open.org/xacml/xacml-rest/v1.0/xacml-rest-v1.0.html). You can still use ACLs with this same authorizer as you would with the out-of-the-box one. XACML evaluation must be enabled explicitly by setting a specific property as described later below. *XACML evaluation* here stands for the extra process of getting a XACML authorization decision from a remote PDP according to the REST Profile of XACML 3.0.

The authorizer combines Kafka ACL evaluation with XACML evaluation similarly to the XACML policy combining algorithm *deny-unless-permit*, with ACL evaluation first. More precisely: * If ACL evaluation returns Permit, final result is Permit.
* Else: 
  * If XACML evaluation is enabled, the final result is the result of XACML evaluation
  * Else Deny.
  
## Installation guide
Get the `tar.gz` distribution from the latest Github release

To enable the authorizer on Kafka, set the server's property: 

`authorizer.class.name=org.ow2.authzforce.kafka.pep.CombinedXacmlAclAuthorizer`

To enable XACML evaluation, set the extra following authorizer properties:
* `org.ow2.authzforce.kafka.pep.xacml.pdp.url`: RESTful XACML PDP resource's URL (e.g. https://services.example.com/pdp), as defined by [REST Profile of XACML 3.0](http://docs.oasis-open.org/xacml/xacml-rest/v1.0/xacml-rest-v1.0.html), §2.2.2
* `org.ow2.authzforce.kafka.pep.xacml.req.tmpl`: [Freemarker](https://freemarker.apache.org/) template of XACML Request formatted according to [JSON Profile of XACML 3.0](http://docs.oasis-open.org/xacml/xacml-json-http/v1.0/xacml-json-http-v1.0.html), in which you can use [Freemarker expressions](https://freemarker.apache.org/docs/dgui_template_exp.html), enclosed between `${` and `}`, and have access to the following [top-level variables](https://freemarker.apache.org/docs/dgui_template_exp.html#dgui_template_exp_var_toplevel) from Kafka's authorization context:

| Variable name | Variable type | Description |
| --- | --- | --- |
|`client` | [java.net.InetAddress](https://docs.oracle.com/javase/8/docs/api/java/net/InetAddress.html) | client/user host name or IP address |
|`principal`| [org.apache.kafka.common.security.auth.KafkaPrincipal](https://kafka.apache.org/11/javadoc/org/apache/kafka/common/security/auth/KafkaPrincipal.html)| user principal|
|`operation`|[org.apache.kafka.common.acl.AclOperation](http://kafka.apache.org/11/javadoc/index.html?org/apache/kafka/common/acl/AclOperation.html)|operation|
|`resourceType`|[org.apache.kafka.common.resource.ResourceType](https://kafka.apache.org/11/javadoc/org/apache/kafka/common/resource/ResourceType.html)|resource type|
|`resourceName`|`String`|resource name|


For example (use your favorite JSON beautifier to make it more readable):
 
```json
org.ow2.authzforce.kafka.pep.xacml.req.tmpl={"Request":{"Category":[{"CategoryId":"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject","Attribute":[{"AttributeId":"urn:oasis:names:tc:xacml:1.0:subject:subject-id","DataType":"urn:oasis:names:tc:xacml:1.0:data-type:x500Name","Value":"${cert.subjectX500Principal}"}]},{"CategoryId":"urn:oasis:names:tc:xacml:3.0:attribute-category:action","Attribute":[{"AttributeId":"urn:oasis:names:tc:xacml:1.0:action:action-id","Value":"${action}",}]},{"CategoryId":"urn:oasis:names:tc:xacml:3.0:attribute-category:resource","Attribute":[{"AttributeId":"urn:oasis:names:tc:xacml:1.0:resource:resource-id","Value":"${topic}"}]}]}}
```

