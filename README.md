# xfon

[![Build Status](https://travis-ci.com/odacremolbap/xfon.svg?branch=master)](https://travis-ci.com/odacremolbap/xfon) [![codecov](https://codecov.io/gh/odacremolbap/xfon/branch/master/graph/badge.svg)](https://codecov.io/gh/odacremolbap/xfon)  [![Go Report Card](https://goreportcard.com/badge/github.com/odacremolbap/xfon)](https://goreportcard.com/report/github.com/odacremolbap/xfon)



Tool for very simple certificate signing


Build with `mage`

## Usage


Create RSA key
```
./xfon rsa new --bits 4096 --out local/ca.key
```

Create CA certificate

```
./xfon x509 new --ca true --cert-out local/ca.crt --key-in local/ca.key \
    --days 365 --common-name myCN --organization myOrg \
    --usages KeyUsageKeyEncipherment,KeyUsageDigitalSignature

```

Create Signed CA certificate

```
./xfon rsa new --bits 4096 --out local/server.key

./xfon x509 signed --cert-out local/server.crt --key-in local/server.key \
    --parent-cert local/ca.crt --signing-key local/ca.key \
    --days 365 --common-name serverCN --organization myOrg \
    --ip-addresses 192.168.0.30,127.0.0.1 \
    --dns-addresses localhost,myserver.local \
    --usages KeyUsageKeyEncipherment,KeyUsageDigitalSignature \
    --ext-usages ExtKeyUsageServerAuth,ExtKeyUsageClientAuth
    

```
