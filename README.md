# aws-tools
Collection of tools to help with local development
on AWS

## update-sts-credentials.py

Usage: `$(eval update-sts-credentials.py profileName accountId userName MFAToken)`

This script will fetch STS credentials using
the existing credentials in your `~/.aws/config`
file.  It will then make a copy of your existing
credentials and replace them in `~/.aws/config`
with the STS credentials.

The script will output `export AWS_...=`
statements that can be sourced in a shell
to have them availble for use in scripts and tools
that do not use the `~/.aws/credentials` file
natively

Place the following in your relevant dotfile to
make the most of the tool:
```bash
function use-aws-myprofile {
  utilPath="/Users/amatheny/code/aws-utils/"
  $(eval ${utilPath}/update-sts-credentials.py myprofile 13132351668 Andrew $1)
}
```

This approach is most useful for when you want to
have destructive API operations restricted by MFA

To have something like this setup, create an IAM
group with two policies, one the vanilla AWS
provided ReadOnly policy, and the other an inline
policy with the following json

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                }
            }
        }
    ]
}
```
