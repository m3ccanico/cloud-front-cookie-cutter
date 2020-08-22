from datetime import datetime, timedelta, timezone

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from botocore.signers import CloudFrontSigner


class CloudFrontCookieCutter(CloudFrontSigner):
    def __init__(self, private_key_file, key_pair_id):
        self._private_key_file = private_key_file
        self._key_pair_id = key_pair_id

    def _rsa_signer(self, message):
        with open(self._private_key_file, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )
            return private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())

    def cut(self, url, date_less_than, secure=True):
        """
        generate the Cloudfront download distribution signed cookies
        :param resource: The object or path of resource.
                         Examples: 'dir/object.mp4', 'dir/*', '*'
        :param expire_minutes:  The number of minutes until expiration
        :param secure: use https or http protocol for Cloudfront URL - update
                       to match your distribution settings.
        :return: Cookies to be set
        """
        policy = self.build_policy(url, date_less_than)
        policy_b = policy.encode("utf8")
        policy_e = self._url_b64encode(policy_b).decode("utf8")

        signature = self._rsa_signer(policy_b)
        signature_e = self._url_b64encode(signature).decode("utf8")

        cookies = {
            "CloudFront-Policy": policy_e,
            "CloudFront-Signature": signature_e,
            "CloudFront-Key-Pair-Id": self._key_pair_id,
        }
        return cookies


if __name__ == "__main__":
    # The root URL of your domain
    url = "https://www.example.com/*"
    # generate/download or upload your private key file as described here
    # https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-trusted-signers.html#private-content-creating-cloudfront-key-pairs
    private_key_file = "/path/to/your/private/key/file.pem"
    # get the key pair ID from the same place
    key_pair_id = "APKAI01234567890ABCD"

    # resource policy will expire in 300 seconds
    date_less_than = datetime.now(timezone.utc) + timedelta(seconds=300)

    cc = CloudFrontCookieCutter(
        private_key_file=private_key_file, key_pair_id=key_pair_id,
    )
    cookies = cc.cut(url=url, date_less_than=date_less_than)

    print(cookies)
    # this just generates and prints the cookies
    # you'll need to write some code to return them to the web browser (e.g. inside a Lambda function)
