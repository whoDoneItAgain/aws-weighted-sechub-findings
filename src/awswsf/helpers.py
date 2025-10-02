import configparser
import json
import logging
import sys
from pathlib import Path

from boto3 import Session
from botocore import exceptions

LOGGER = logging.getLogger("awswsf")


def format_json_string(json_string):
    """Format the given JSON string."""
    return json.dumps(json_string, indent=1, sort_keys=True, separators=(",", ": "))


def get_boto3_session(profile_name):
    if profile_name == "default":
        session = Session()

    else:
        config = configparser.ConfigParser()
        config.read(Path("~/.aws/config").expanduser())

        aws_profiles = []
        for k in config:
            if k.startswith("profile "):
                profile = (k.split(" ", 1))[1]
                aws_profiles.append(profile)

        if profile_name in aws_profiles:
            session = Session(profile_name=profile_name)
        else:
            LOGGER.error(
                f"Profile '{profile_name}' was not found",
            )
            sys.exit(1)

    try:
        session = Session(profile_name=profile_name)
        sts_client = session.client("sts")
        sts_client.get_caller_identity()

        LOGGER.info(f"Profile '{profile_name}' is valid and active.")

        return Session(profile_name=profile_name)

    except exceptions.SSOTokenLoadError:
        LOGGER.error(
            f"Profile '{profile_name}' could not be loaded.",
        )
        sys.exit(1)
    except exceptions.TokenRetrievalError:
        LOGGER.error(
            f"Profile '{profile_name}' is expired and could not be refreshed.",
        )
        sys.exit(1)
    except exceptions.ClientError as e:
        if "ExpiredToken" in str(e):
            LOGGER.error(
                f"Profile '{profile_name}' is inactive or expired: {e}",
            )
            sys.exit(1)

        else:
            LOGGER.error(
                f"An unexpected error occurred while checking session for profile '{profile_name}': {e}",  # noqa: E501
            )
            sys.exit(1)
