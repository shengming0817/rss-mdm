# Apple manufacturer roots

DER trust anchors for the CMS MachineInfo chain. Retrieved directly from Apple on 2026-10-05; no system/web-PKI roots are accepted by this verifier. Production trust is compiled from these files. Controlled T2 roots are available only through the integration feature.

- [AppleIncRootCertificate.cer](https://www.apple.com/appleca/AppleIncRootCertificate.cer) — SHA-256 `b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024`
- [AppleRootCA-G3.cer](https://www.apple.com/certificateauthority/AppleRootCA-G3.cer) — SHA-256 `63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179`

Review Apple root publication and supported-device chains before replacing this set. Profile, SCEP and APNs issuers remain independent.

Root membership alone does not identify a manufacturing certificate. The verifier follows Apple's [`SecPolicyCreateiPhoneDeviceCertificate`](https://github.com/apple-oss-distributions/Security/blob/main/OSX/sec/Security/SecPolicy.c): exactly one CMS signer, issuer CN `Apple iPhone Device CA`, and a cryptographically verified four-certificate chain to these anchors. Apple's basic device policy omits certificate validity windows; this identified manufacturing chain also requires acceptance of its historical SHA-1 / RSA-1024 CA. These exceptions apply only after the device issuer check, and CMS content signatures remain verified. Ordinary profile/developer certificates sharing an Apple root are rejected. Controlled T2 proves this policy using an expired manufacturing CA and a same-root non-device signer. Actual supported Mac chains and Setup Assistant behavior remain T3 acceptance requirements.
