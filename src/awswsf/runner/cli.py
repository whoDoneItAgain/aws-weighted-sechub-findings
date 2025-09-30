import configparser
import logging
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from awswsf.config import ConfigMixIn, configure_logging

LOGGER = logging.getLogger(__name__)


class Runner:
    def __init__(self, config: ConfigMixIn) -> None:
        self.config = config

    def _get_boto3_session(self):
        profile_name = self.config.profile

        if profile_name == "default":
            return boto3.session.Session()

        config = configparser.ConfigParser()
        config.read(Path("~/.aws/config").expanduser())

        aws_profiles = []
        for k in config:
            if k.startswith("profile "):
                profile = (k.split(" ", 1))[1]
                aws_profiles.append(profile)

        if profile_name in aws_profiles:
            try:
                session = boto3.session.Session(profile_name=profile_name)
                sts_client = session.client("sts")
                sts_client.get_caller_identity()

                LOGGER.info(f"SSO session for profile '{profile_name}' is active.")

                return boto3.session.Session(profile_name=profile_name)

            except ClientError as e:
                if "ExpiredToken" in str(e) or "SSOTokenLoadError" in str(e):
                    LOGGER.error(
                        f"SSO session for profile '{profile_name}' is inactive or expired: {e}",
                    )
                    sys.exit(1)
                else:
                    LOGGER.error(
                        f"An unexpected error occurred while checking SSO session for profile '{profile_name}': {e}",
                    )
                    sys.exit(1)

        msg = "Profile Not Found"
        raise Exception(msg)

    def cli(self) -> None:
        configure_logging(self.config.debug, self.config.info)

        LOGGER.info("test info")

        LOGGER.debug("Configuration:")
        LOGGER.debug(self.config)

        self.aws_session = self._get_boto3_session()


def main() -> None:
    try:
        config = ConfigMixIn(sys.argv[1:])
    except Exception as e:
        print(e)
        sys.exit(1)
    runner = Runner(config)
    runner.cli()


if __name__ == "__main__":
    main()
