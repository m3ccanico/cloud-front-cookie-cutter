from datetime import datetime, timedelta, timezone

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from botocore.signers import CloudFrontSigner
from botocore.compat import six

KEY_FILE = "/path/to/your/private/key/file.pem"


def rsa_signer(message):
    """
    Signs a message with the key file.

    :param message: The message to be signed.
    """

    with open(KEY_FILE, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
        return private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())


class CloudFrontCookieSigner(CloudFrontSigner):
    def __init__(self, key_id, rsa_signer):
        """Create a CloudFrontCookieCutter.

        :type key_id: str
        :param key_id: The CloudFront Key Pair ID
        
        :type rsa_signer: callable
        :param rsa_signer: An RSA signer.
               Its only input parameter will be the message to be signed,
               and its output will be the signed content as a binary string.
               The hash algorithm needed by CloudFront is SHA-1.
        """
        super().__init__(key_id, rsa_signer)

    def generate_signed_cookies(self, url, date_less_than=None, policy=None):
        """
        Cuts the CloudFront signed cookies.

        :type url: str
        :param url: The URL of the protected object
        
        :type date_less_than: datetime
        :param date_less_than: The URL will expire after that date and time

        :type policy: str
        :param policy: The custom policy, possibly built by self.build_policy()

        :rtype: dict
        :return: A dicts of cookie values.
        """
        if (
            date_less_than is not None
            and policy is not None
            or date_less_than is None
            and policy is None
        ):
            e = "Need to provide either date_less_than or policy, but not both"
            raise ValueError(e)
        if date_less_than is not None:
            # We still need to build a canned policy for signing purpose
            policy = self.build_policy(url, date_less_than)
        if isinstance(policy, six.text_type):
            policy = policy.encode("utf8")

        signature = self.rsa_signer(policy)

        cookies = {
            "CloudFront-Policy": self._url_b64encode(policy).decode("utf8"),
            "CloudFront-Signature": self._url_b64encode(signature).decode("utf8"),
            "CloudFront-Key-Pair-Id": self.key_id,
        }
        return cookies


if __name__ == "__main__":
    # The root URL of your domain
    url = "https://www.example.com/*"
    # generate/download or upload your private key file as described here
    # https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-trusted-signers.html#private-content-creating-cloudfront-key-pairs

    # get the key pair ID from the same place
    key_id = "APKAI01234567890ABCD"

    # resource policy will expire in 300 seconds
    date_less_than = datetime.now(timezone.utc) + timedelta(seconds=300)

    signer = CloudFrontCookieSigner(key_id=key_id, rsa_signer=rsa_signer)
    cookies = signer.generate_signed_cookies(url=url, date_less_than=date_less_than)

    print(cookies)
    # this just generates and prints the cookies
    # you'll need to write some code to return them to the web browser (e.g. inside a Lambda function)
