## Wildcert

A CLI tool for generating wildcard certificates via Let’s Encrypt using the DNS-01 challenge.

### Requirements

* Go SDK installed
* A domain with permission to create DNS records

### Usage

```bash
export HOST=sample.com
export EMAIL=user@sample.com
go build
./wildcert
```

The Email address is used for Let's Encrypt notifications. A certificate for the domains `*.sample.com` and `sample.com` will be generated and saved in the `certs` directory. The certificate will be valid for 90 days.

### License

This project is licensed under the 0BSD Open Source License - see the [LICENSE](LICENSE) file for details.