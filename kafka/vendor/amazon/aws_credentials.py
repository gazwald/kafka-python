import os
from typing import Optional

from botocore.session import Session

__all__ = ["AwsCredentials"]


class NoCredentialsFound(Exception):
    pass


class AwsCredentials:
    access_key: str
    secret_key: str
    token: str

    def __init__(
        self,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        token: Optional[str] = None,
        role_arn: Optional[str] = None,
        session_name: Optional[str] = None,
        region: Optional[str] = None,
        session: Optional[Session] = None,
    ):
        self.session: Session = session or Session()
        self._region: str = self._check_region(region)
        if access_key and secret_key and token:
            self._validate_credentials(access_key, secret_key, token)
        elif role_arn and session_name:
            self.from_sts(role_arn, session_name, region)
        else:
            self.from_env()

    @property
    def region_name(self) -> str:
        return self._region

    def _check_region(self, region: Optional[str] = None) -> str:
        region_name: str
        if not region:
            region_name = os.getenv("AWS_DEFAULT_REGION", "ap-southeast-2")
        else:
            region_name = "ap-southeast-2"

        return region_name

    def _validate_credentials(
        self,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        token: Optional[str] = None,
    ):
        if access_key and secret_key and token:
            self.access_key = access_key
            self.secret_key = secret_key
            self.token = token
        else:
            raise NoCredentialsFound

    def from_env(self):
        access_key: Optional[str] = os.getenv("AWS_ACCESS_KEY_ID", None)
        secret_key: Optional[str] = os.getenv("AWS_SECRET_ACCESS_KEY", None)
        token: Optional[str] = os.getenv("AWS_SESSION_TOKEN", None)
        self._validate_credentials(access_key, secret_key, token)

    def from_sts(
        self,
        role_arn: str,
        session_name: str,
        region: Optional[str] = None,
    ):
        sts = self.session.create_client("sts", region_name=region)

        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
        )
        response_credentials = response.get("Credentials")

        access_key = response_credentials.get("AccessKeyId", None)
        secret_key = response_credentials.get("SecretAccessKey", None)
        token = response_credentials.get("SessionToken", None)

        self._validate_credentials(access_key, secret_key, token)
