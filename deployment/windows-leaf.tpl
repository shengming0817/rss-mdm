{
  "subject": {"commonName": {{ toJson .Token.sub }}},
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["clientAuth"],
  "basicConstraints": {"isCA": false}
}
