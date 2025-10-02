import logging
import sys

from awswsf.config import ConfigMixIn, configure_logging
from awswsf.helpers import get_boto3_session

LOGGER = logging.getLogger(__name__)

STANDARDS_MAP: dict = {
    "FSBP": {
        "arn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
    },
}


class Runner:
    def __init__(self, config: ConfigMixIn) -> None:
        self.config = config

    def _get_standards_for_control(self, control):
        control_standards: list = []
        sechub_client = self.aws_session.client("securityhub")

        response = sechub_client.list_security_control_definitions(
            StandardsArn=STANDARDS_MAP[control]["arn"],
            MaxResults=100,
        )

        LOGGER.info(response["SecurityControlDefinitions"])

    def cli(self) -> None:
        configure_logging(self.config.debug, self.config.info)

        LOGGER.info("Info Logging Active")
        LOGGER.debug("Debug Logging Active")

        LOGGER.debug("Configuration:")
        LOGGER.debug(self.config)

        self.aws_session = get_boto3_session(self.config.profile)

        self._get_standards_for_control("FSBP")


def main() -> None:
    try:
        config = ConfigMixIn(sys.argv[1:])
    except Exception as e:  # noqa: BLE001
        print(e)  # noqa: T201
        sys.exit(1)
    runner = Runner(config)
    runner.cli()


if __name__ == "__main__":
    main()
