# dnscrypt-transport

An incomplete golang library to provide DNSCrypt support to DNSFilter

** NOTE: This project was scrapped after only being partially completed and is not currently functional. We are currently focusing all our efforts on DNS over TLS. We are releasing this project in case anyone else finds it useful, or expresses enough interest to help us complete it. **

## Generate provider secret & public key

This generates the long-term provider key pair.

```
dnscrypt-mgmt generate-provider-key >provider.key
```

The output contains both the private and the public key. The public
key should be distributed to users and can be extracted with

```
dnscrypt-mgmt print-public-key provider.key
```

The private key will be required when generating certificates.

## Generate certificate

This generates a short-lived (24h) certificate with its own,
short-lived key pair. The certificate is signed with the provider
secret key.

```
dnscrypt-mgmt generate-certificate provider.key >cert.cert
```

The output file containts the certificate, the private key and the
public key. Make the entire file available to the resolver.
