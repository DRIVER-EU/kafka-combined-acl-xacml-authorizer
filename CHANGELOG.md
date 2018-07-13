# Change log
All notable changes to this project are documented in this file following the [Keep a CHANGELOG](http://keepachangelog.com) conventions.


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