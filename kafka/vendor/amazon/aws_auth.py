import hmac
import logging
from collections import OrderedDict
from datetime import datetime
from hashlib import sha256
from typing import Dict, List
from urllib.parse import quote

from kafka.vendor.amazon.aws_credentials import AwsCredentials

__all__ = ["AwsSig4Auth"]


log = logging.getLogger(__name__)


class AwsSig4Auth:
    action: str = "kafka-cluster:Connect"
    algorithm: str = "AWS4-HMAC-SHA256"
    canonical_uri: str = "/"
    empty_sha256_hash: str = (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    expires_in_seconds: str = "900"
    headers_to_sign: Dict[str, str]
    host: str
    method: str = "GET"
    region: str
    service: str = "kafka-cluster"
    user_agent: str = "kafka-python-iam"
    version: str = "2020_10_22"

    now: datetime = datetime.utcnow()
    timestamp: str = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp: str = now.strftime("%Y%m%d")

    def __init__(
        self,
        host: str,
        credentials: AwsCredentials,
    ):
        self.region: str = credentials.region_name
        self.host: str = host
        self.credentials: AwsCredentials = credentials
        self.headers_to_sign = {"host": host}

    @property
    def access_key(self) -> str:
        return self.credentials.access_key

    @property
    def secret_key(self) -> str:
        return self.credentials.secret_key

    @property
    def token(self) -> str:
        return self.credentials.token

    @staticmethod
    def _encode(msg: str, encoding: str = "utf-8") -> bytes:
        return msg.encode(encoding)

    def _hash_string(self, msg: str) -> str:
        return sha256(self._encode(msg)).hexdigest()

    def _sign_bytes(self, key: bytes, msg: str) -> bytes:
        msg_bytes: bytes = self._encode(msg)
        return hmac.new(key, msg_bytes, sha256).digest()

    def _sign_bytes_as_hex(self, key: bytes, msg: str) -> str:
        msg_bytes: bytes = self._encode(msg)
        return hmac.new(key, msg_bytes, sha256).hexdigest()

    @staticmethod
    def uri_encode(input_str: str, encode_slash: bool = True) -> str:
        safe: str = "-_.~"
        if not encode_slash:
            safe += "/"

        result: str = quote(input_str, safe=safe)
        log.debug("uri_encode: %s", result)
        return result

    def canonical_query_dict(
        self, uriencoded: bool = True, lower_case: bool = False
    ) -> OrderedDict[str, str]:
        params: OrderedDict[str, str] = OrderedDict()

        params["Action"] = self.action
        params["X-Amz-Algorithm"] = self.algorithm
        params["X-Amz-Credential"] = self.scope()
        params["X-Amz-Date"] = self.timestamp
        params["X-Amz-Expires"] = self.expires_in_seconds
        params["X-Amz-Security-Token"] = self.token
        params["X-Amz-SignedHeaders"] = self.signed_headers

        if lower_case:
            params = OrderedDict((key.lower(), value) for key, value in params.items())

        if uriencoded:
            params = OrderedDict(
                (self.uri_encode(key, encode_slash=False), self.uri_encode(value))
                for key, value in params.items()
            )

        return params

    @property
    def canonical_query_string(self) -> str:
        params: OrderedDict[str, str] = self.canonical_query_dict()
        result: str = "&".join([f"{k}={v}" for k, v in params.items()])
        logging.debug("canonical_query_string: %s", result)
        return result

    @property
    def canonical_headers(self) -> str:
        headers: str = f"host:{self.host}\n"
        return headers

    @property
    def signed_headers(self) -> str:
        return "host"

    def canonical_request(self) -> str:
        request: List[str] = []
        request.append(self.method.upper())
        request.append(self.canonical_uri)
        request.append(self.canonical_query_string)
        request.append(self.canonical_headers)
        request.append(self.signed_headers)
        request.append(self.empty_sha256_hash)
        result: str = "\n".join(request)
        logging.debug("cannonical_request: %s", result)
        return result

    def scope(self) -> str:
        scope: List[str] = []
        scope.append(self.access_key)
        scope.append(self.datestamp)
        scope.append(self.region)
        scope.append(self.service)
        scope.append("aws4_request")
        result: str = "/".join(scope)
        logging.debug("scope: %s", result)
        return result

    def string_to_sign(self) -> str:
        canonical_request = self.canonical_request()
        string_to_sign: List[str] = []
        string_to_sign.append(self.algorithm)
        string_to_sign.append(self.timestamp)
        string_to_sign.append(self.scope())
        string_to_sign.append(self._hash_string(canonical_request))
        result: str = "\n".join(string_to_sign)
        logging.debug("string_to_sign: %s", result)
        return result

    def signature(self) -> str:
        key: bytes = self._encode(f"AWS4{self.credentials.secret_key}")

        date_key: bytes = self._sign_bytes(key, self.datestamp)
        date_region_key: bytes = self._sign_bytes(date_key, self.region)
        date_region_service_key: bytes = self._sign_bytes(date_region_key, self.service)

        signing_key: bytes = self._sign_bytes(date_region_service_key, "aws4_request")
        signature: str = self._sign_bytes_as_hex(signing_key, self.string_to_sign())
        return signature
