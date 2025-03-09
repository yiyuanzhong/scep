# SCEP
Inspired by micromdm/scep, I want a simple SCEP service lightweight enough for embedded environment to issue and renew certificates for my in-house devices. While the issuance process must still be done in a trusted environment (physically present and connected to a specific network), the renewal shall be automatic and remote.

## Background
While it does have a lot of use cases in enterprise environments, it's not strictly necessary for home users to deal with certificates unless you're a paranoid to deploy certificate based authentication / authorization (like EAP-TLS secured home Wi-Fi or VPN for Starbucks). You can issue the certificate for the first time with a super long key length with insane validity then forget about it, knowing that doing so is still much more secure than passwords (yes I did that), but with automatic enrollment a more reasonable key length can be used to accelerate the computation since short validity can be used, and you don't have to remember which one expires when.

## But
Simple Certificate Enrollment Protocol (SCEP) is a widely adopted PKI component that allows (semi-)automatic certificate enrollments. There're modern alternatives like Certificate Enrollment Protocol (CEP) but SCEP is still the most supported solution. However it's not comprehensive in many ways. SCEP is built on top of well defined industry standard (CMS/PKCS7) adding some loose workflows and minor requirements, but never narrows down the flexibilities in CMS/PKCS7 enough which has caused major interoperative issues. Meanwhile for home users, at least me, it's impossible to always track the devices and secure the enrollment process so the renewal has to go through Internet which is a uncontrolled environment.

## The design
* A service with minimal dependencies so I can run it in an embedded container.
* Certain degree of configurability to interoperate with multiple clients.
* A dynamic challenge password is intruduced to automate the initial issuance.
* A valid certificate is required to renew the certificates so it's secure over Internet.

## Quick start
You start by getting the signing CA certificate and key, this can be a self-signed root CA or an intermediate CA (which you should have the full chain ready). Only one signing CA is supported, you can however launch multiple instances since it's quite lightweighted.

Other than specifying validity on the command line, issued certificates can have customized extensions by supplying a configure file containing key=value pairs similar to OpenSSL configure syntax.

An automated authorization can be configured so that the SCEP client must present a challenge password, which is generated based on a secret passphrase and the subject as a pre-authorization. This challenge password is expired 7 days after generation.

To start with you can just invoke the server by:
```
./scep -p 8080 -c signing.pem -k signing.key
```

It will start a http server listening on port 8080, URL is ignored so any request like `http://<your IP>:8080/` or `http://<your IP>:8080/abc/def/123` will invoke the service. Since no password is configured the server will sign any SCEP requests, good for testing.

To automatically authorize a certificate, you configure the password by `-C`
```
./scep -p 8080 -c signing.pem -k signing.key -C very-strong-password
```

With a password set, the client must present a challenge string generated by `-S`
```
./scep -C the-same-very-strong-password -S the-subject
```

The subject is encoded in slash delimited key value pairs, for example
```
./scep -C 8rROG5qV -S /C=US/O=github/CN=client28369
```

A 80 bytes challenge string is generated and is valid for 7 days.

In a real world scenario you will want to protect the server by running it behind a TLS reverse proxy, since SCEP doesn't specify where the challenge password should be present, inside the protected payload and/or the plaintext encapsule. In real world macOS will expose the challenge password in plaintext thus any MITM can impersonate the user, and the reason is probably that Apple products do not validate CA certificate at all, thus MITM is always possible with or without a challenge. By default the server will reject the request if it sees challenge password exposed in plaintext, you can allow such requests by passing `-E`.

The extensions are to be defined in a plaintext file, which you should start with the absolute minimum
```
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
```

Then specify the file by `-e`
```
./scep -p 8080 -c signing.pem -k signing.key -e extensions.cnf
```

## Requirements of the signing CA certificate
The daemon requires X509v3 certificate, so if you generate certificate with `openssl x509` you need to specify an extension file so the certificate is V3 instead of V1. The recommended minimum extensions are:
```
basicConstraints=critical,CA:TRUE,pathlen:0
authorityKeyIdentifier=keyid:always
subjectKeyIdentifier=hash
```
This will create the extensions below:
```
X509v3 extensions:
    X509v3 Basic Constraints: critical
        CA:TRUE, pathlen:0
    X509v3 Authority Key Identifier:
        keyid:D4:D7:5C:12:2E:6F:13:97:33:FA:DE:3B:87:BC:8C:54:84:32:58:7E
    X509v3 Subject Key Identifier:
        87:EF:C0:95:80:C5:83:6C:30:69:0B:2A:99:25:8E:0B:39:A5:1D:B0
```
Please check what your signing CA extensions are and they are compatible with your certificates to issue. If no extension file is specified by `-e` the daemon will use these builtin extensions:
```
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
```
Note that it requires the signing CA certificate to have keyid in `SubjectKeyIdentifier` or the it will fail to issue certificates as `keyid:always` unsatisfied. This is a recommended security feature, override it by specifying an extension file which doesn't require `authorityKeyIdentifier=keyid:always`.

## All command line arguments
### Daemon mode
|Arg|Long&nbsp;Argument|Default|Explanation|
|-|-|-|-|
|-p|--port=\<port\>|(mandatory)|Listening port.|
|-c|--ca=\<signca.cer\>|(mandatory)|Signing CA certificate.|
|-k|--key=\<signca.key\>|(mandatory)|Signing CA key.|
|-f|--caform=\<pem\|der\>|pem|Signing CA certificate format.|
|-F|--keyform=\<pem\|der\>|pem|Signing CA key format.|
|-P|--capass=\<password\>|(none)|Signing CA key password.|
|-C|--challenge=\<secret\>|(none)|Require new issues or renewals to carry a challenge password generated by administrator, which are generated (protected) by this secret. All requests are granted (even if they violates other constrains) if no challenge is required.|
|-V|--days=\<valid days\>|90|Validity of issued certificates.|
|-R|--allowrenew=\<days\>|14|Days until expiry before renewals are allowed|
|-d|--depot=\<path\>|(disabled)|Save all accepted challenge passwords and issued certificates inside this directory. It serves two purposes: 1. challenge passwords can only be used once, reusing them will cause original certificates to be redownloaded 1. keep records of what certificates have been issued. No cleanup is performed, external file rotation is needed. |
|-e|--extensions=\<file\>|(disabled)|Load an OpenSSL extension file to customize issued certificates.|
|-l|--chain=\<chain.cer\>|(none)|At most 8 intermediate/root CA certificates can be specified which will be provided in GetCACert response, and the downloaded along with the issued certificates. This is usually required if the signing CA is not the root CA even if the root CA has been preinstalled on clients. Specify in leaf to root order.|
|-L|--chainform=\<pem\|der\>|pem|Specify the same number of times as chained CA if needed.|
|-o|--otherca=\<other.cer\>|(none)|When the client renews its certificate with an existing certificate, the daemon will check if that certificate was issued by the signing CA itself. Specifying additional CA certificates so the client certificate is validated against all of them. The specified CA certificates are formed as a CA store thus every certificate is a trust anchor. Since the client might not provide the whole certificate chain, it's recommended to include all previously active signing CAs so the validation is more stable.|
|-O|--otherform=\<pem\|der\>|pem|Specify the same number of times as other CA if needed.|
|-T|--trans_id|(unchecked)|Enable Transaction ID check in the requests. Note that only a subset of allowed Transaction ID methods (as in RFC5280 and RFC7093) are supported, so you might want to disable this check if you have client requests rejected.|
|-E|--exposed_cp|(enforced)|Challenge passwords shall be encrypted in the inner payload of PKCS/7 envelope otherwise they can be eavesdropped and hijacked. However not all the clients properly implement this requirements and might cause security concerns so by default the daemon will reject such requests. Specifying this argument turns off this check. *NOT RECOMMENDED* |
|-A|--set_san|(discarded)|CSR can contain Subject Alternative Name (SAN) which can be copied to the newly issued certificates, however such SANs are not protected by challenge passwords and the clients can request any SAN that they want, so by default the daemon will not copy them. Specifying this argument allows such copying.|
### Challenge generation mode
|Arg|Long&nbsp;Argument|Value|Explanation|
|-|-|-|-|
|-C|--challenge=\<secret\>|(mandatory)|Password used to generate challenge passwords based on subject, the generated challenge password is valid for 7 days.|
|-S|--subject=\<subject\>|(mandatory)|X509 subject identifier in the format of `/key=value/key=value`. Example: `/C=AU/ST=Queensland/O=CryptSoft Pty Ltd/CN=Server test cert` |
