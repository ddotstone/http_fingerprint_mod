# Apache Logging Module with ClientHello Fingerprint, HTTP Headers, and TLS RTT

## Overview

This Apache module extends the default logging capabilities by capturing additional details such as:
- **ClientHello Fingerprint Data**
- **HTTP Headers**
- **TLS Round-Trip Time (RTT)**
- **Client IP**

The captured data is formatted in JSON for easy parsing and analysis.

## Features
- Logs ClientHello fingerprint to identify TLS client characteristics for mod_ssl
- Captures full HTTP headers for each request
- Logs TLS handshake round-trip time (RTT) from mod_ssl
- Outputs logs in structured JSON format

## Requirements
- Apache HTTP Server (version 2.51 or higher)
- OpenSSL development libraries
- `apxs` (Apache Extension Tool)

## Installation

1. **Prerequisites:**
   - Apache HTTP Server (version 2.51 or higher)
   - OpenSSL development libraries
   - `apxs` (Apache Extension Tool)

2. **Build and Install:**
   ```bash
   make install
   ```

3. **Enable the Module:**
   ```bash
   a2enmod http_fingerprint_log
   systemctl restart apache2
   ```

## Configuration

Add the following configuration in your Apache `httpd.load` or a virtual host configuration file:

```apache

LoadModule http_fingerprint_log_module /usr/lib/apache2/modules/mod_http_fingerprint_log.so

```
Add the following configuration in your Apache `httpd.conf` or a virtual host configuration file:
```apache

FingerprintLog logs/custom_log

```

## Log Format Example

```json
{"id":"Z6w5UmyArOEoR0Tw5ZFD9wAAAEE",
"ip":"255.255.255.255",
"ssl_clienthello_version":"0303",
"ssl_clienthello_ciphers":"3a3a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035",
"ssl_clienthello_sig_algos":"04030804040105030805050108060601",
"ssl_clienthello_groups":"5a5a11ec001d00170018",
"ssl_clienthello_ec_formats":"00",
"ssl_clienthello_alpn":"02683208687474702f312e31",
"ssl_clienthello_versions":"fafa03040303",
"ssl_clienthello_extensions":"0005000d000a002b001200000017ff010033001b000b00100023002d",
"ssl_handshake_rtt":"6529",
"headers":"GET / HTTP/1.1|Host:capstonebyu|Connection:keep-alive|Cache-Control:max-age=0|sec-ch-ua:\"Not A(Brand\";v=\"8\", \"Chromium\";v=\"132\", \"Google Chrome\";v=\"132\"|sec-ch-ua-mobile:?0|sec-ch-ua-platform:\"Windows\"|Upgrade-Insecure-Requests:1|User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36|Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7|Sec-Fetch-Site:none|Sec-Fetch-Mode:navigate|Sec-Fetch-User:?1|Sec-Fetch-Dest:document|Accept-Encoding:gzip, deflate, br, zstd|Accept-Language:en-US,en;q=0.9,pt-BR;q=0.8,pt;q=0.7,ja-JP;q=0.6,ja;q=0.5"
}
```

## Dependencies
- OpenSSL for TLS handshake analysis
- Apache HTTP Server 2.51+

## Troubleshooting
- **Module not loading?** Check `httpd -M` to confirm the module is enabled.
- **Permission errors?** Ensure Apache has the necessary permissions to write logs.
- **Incorrect data?** Validate OpenSSL version compatibility.

## License
This project is licensed under the Apache License 2.0.

## Contributing
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/fooBar`)
