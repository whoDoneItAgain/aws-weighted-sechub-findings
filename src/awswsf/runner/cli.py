import logging
import sys

from awswsf.config import ConfigMixIn, configure_logging
from awswsf.helpers import get_boto3_session

LOGGER = logging.getLogger(__name__)


class Runner:
    def __init__(self, config: ConfigMixIn) -> None:
        self.config = config

    def cli(self) -> None:
        configure_logging(self.config.debug, self.config.info)

        LOGGER.info("Info Logging Active")
        LOGGER.debug("Debug Logging Active")

        LOGGER.debug("Configuration:")
        LOGGER.debug(self.config)

        self.aws_session = get_boto3_session(self.config.profile)


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
