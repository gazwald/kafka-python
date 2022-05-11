import json
import os
from collections import OrderedDict
from typing import Optional

from kafka.vendor.amazon.aws_auth import AwsSig4Auth
from kafka.vendor.amazon.aws_credentials import AwsCredentials

AWS_ASSUME_ROLE_ARN: str = "AWS_ASSUME_ROLE_ARN"
AWS_ASSUME_SESSION_NAME: str = "AWS_ASSUME_SESSION_NAME"
DEFAULT_SESSION_NAME: str = "aws-msk-iam-client"

__all__ = ["AwsMskIamClient"]


class AwsMskIamClient:
    def __init__(self, host: str):
        self.auth = AwsSig4Auth(
            host=host,
            credentials=self._get_credentials(),
        )

    @property
    def first_message(self) -> bytes:
        parameters: OrderedDict[str, str] = self._create_parameters()
        message: bytes = self._json_encode(parameters)
        return message

    @staticmethod
    def _get_credentials() -> AwsCredentials:
        role_arn: Optional[str] = os.getenv(AWS_ASSUME_ROLE_ARN)
        session_name: str = os.getenv(AWS_ASSUME_SESSION_NAME, DEFAULT_SESSION_NAME)

        return AwsCredentials(role_arn=role_arn, session_name=session_name)

    @staticmethod
    def _json_encode(parameters: OrderedDict[str, str]) -> bytes:
        json_payload: str = json.dumps(
            parameters, separators=(",", ":"), ensure_ascii=False
        )
        return json_payload.encode("utf-8")

    def _create_parameters(self) -> OrderedDict[str, str]:
        parameters: OrderedDict[str, str] = OrderedDict()

        parameters["version"] = self.auth.version
        parameters["host"] = self.auth.host
        parameters["user-agent"] = self.auth.user_agent
        parameters.update(
            self.auth.canonical_query_dict(uriencoded=False, lower_case=True)
        )
        parameters["x-amz-signature"] = self.auth.signature()

        return parameters
