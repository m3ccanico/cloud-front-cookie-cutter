# CloudFront Cookie Cutter

An extension of the BotoCore [CloudFrontSigner class](https://github.com/boto/botocore/blob/develop/botocore/signers.py) that helps generating signed cookies to authenticate against CloudFront distributions. The [official documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudfront.html#generate-a-signed-url-for-amazon-cloudfront) only contains an example how to create a signed URLs.

## Installation

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

To run the example code, you'll need to create a private/public key pair (see [official documentation](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-trusted-signers.html#private-content-creating-cloudfront-key-pairs)). Then update the variables in the code and run:

```sh
python cookie_cutter.py
```
