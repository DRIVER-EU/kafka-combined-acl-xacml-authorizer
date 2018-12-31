# Change log
All notable changes to this project are documented in this file following the [Keep a CHANGELOG](http://keepachangelog.com) conventions.


## 1.2.0
### Changed
- Maven parent project version (authzforce-ce-parent): 7.5.0
- Dependency versions:
	- authzforce-ce-jaxrs-utils: 1.3.0
		- authzforce-ce-xacml-json-model: 2.1.0
	- Kafka_2.12: 2.0.0
	- Freemarker: 2.3.28
- Copyright company name in license headers

### Added
- #6 : authorization attribute for Kafka consumer group ID added to (XACML) authorization requests to PDP, in order to allow group-based access control; the Kafka consumer's group ID is retrieved when the consumer joins the group (assuming the READ operation on the group - corresponds to group join in Kafka API model - has been authorized).

### Fixed
- #2 : CVE-2018-7489, CVE-2014-0085, CVE-2015-4345


## 1.1.0
### Fixed
- Bad tagging
- Release on Maven Central


## 1.0.0
### Changed 
- Maven project version: authzforce-ce-parent: 7.4.0 -> Upgrade Apache CXF version (to fix a CVE): 3.2.5
- Maven dependency versions:
	- Spring Framework: 4.3.18 (fix CVE-2018-8014)
	- authzforce-ce-jaxrs-utils: 1.2.0
		- authzforce-ce-xacml-json-model: 2.0.0

### Fixed
- Spring Framework logging: replaced commons-logging with jcl-over-slf4j for SLF4j logging

### Added
- - #1: Authorization decision caching
- SSL support with client certificate authentication:
	- New configuration property `org.ow2.authzforce.kafka.pep.http.client.cfg.location` to [configure CXF HTTP client](https://cxf.apache.org/docs/client-http-transport-including-ssl-support.html#ClientHTTPTransport(includingSSLsupport)-ConfiguringSSLSupport), esp. SSL settings


## 0.2.0
### Added 
- XACML Request template file (`request.xacml.json.ft`) as part of the assembled package (`tar.gz`), so that it can be customized (by editing the file) depending on the use case

## 0.1.0
Initial release
