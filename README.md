# xfon

Tool for very simple certificate signing


Build with `mage`

## Usage

```
./xfon rsa new --bits 4096 --out local/key.pem
```

```
./xfon x509 new --ca true --cert-out local/cert.pem --days 10 --key-in local/key.pem

```
