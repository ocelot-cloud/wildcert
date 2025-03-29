## Wildcert

A CLI tool for generating wildcard certificates via Let’s Encrypt using the DNS-01 challenge.

### Requirements

* A domain with permission to create DNS records

### Usage

```bash
export HOST=sample.com
export EMAIL=user@sample.com
./wildcert
```

The Email address is used for Let's Encrypt notifications. A certificate for the domains `*.sample.com` and `sample.com` will be generated and saved in the `certs` directory. The certificate will be valid for 90 days.

### Contributing

Please read the [Community](https://ocelot-cloud.org/docs/community/) articles for more information on how to contribute to the project and interact with others.

### License

This project is licensed under the 0BSD License - see the [LICENSE](LICENSE) file for details.