{
    "Request":
    {
        "Category":
        [
            {
                "CategoryId": "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject",
                "Attribute":
                [
                    {
                        "AttributeId": "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
                        "DataType":"urn:oasis:names:tc:xacml:1.0:data-type:x500Name",
                        "Value": "${cert.subjectX500Principal}"
                    },
                    {
                        "AttributeId": "urn:oasis:names:tc:xacml:3.0:subject:authn-locality:ip-address",
                        "DataType":"urn:oasis:names:tc:xacml:2.0:data-type:ipAddress",
                        "Value": "${clientAddress.hostAddress}"
                    }
                ]
            },

            {
                "CategoryId": "urn:oasis:names:tc:xacml:3.0:attribute-category:action",
                "Attribute":
                [
                    {
                        "AttributeId": "urn:oasis:names:tc:xacml:1.0:action:action-id",
                        "Value": "${action}",
                    }
                ]
            },

            {
                "CategoryId": "urn:oasis:names:tc:xacml:3.0:attribute-category:resource",
                "Attribute":
                [
                    {
                        "AttributeId": "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
                        "Value": "${topic}"
                    }
                ]
            }
        ]
    }
}
