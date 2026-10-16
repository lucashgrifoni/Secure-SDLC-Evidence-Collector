# Checkov capture

Written by Checkov 3.3.19 on 2026-10-16. Checkov names its output file
`results_sarif.sarif`; it was renamed to `checkov.sarif`, content
unchanged.

```sh
BC_SKIP_MAPPING=TRUE checkov -d tf --framework terraform --skip-download \
  --compact --quiet -o sarif --output-file-path out
```

Checkov exited 1. The SARIF has driver `Checkov`, ten rules with
`defaultConfiguration.level` `error`, and ten results with `level: error`
and a `ruleIndex`.

`tf/main.tf`:

```hcl
resource "aws_s3_bucket" "logs" {
  bucket = "example-logs"
}

resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```
