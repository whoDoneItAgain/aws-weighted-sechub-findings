import argparse
import logging
from collections.abc import Sequence

from awswsf.helpers import format_json_string

LOGGER = logging.getLogger("awswsf")


def configure_logging(debug, info):
    ch = logging.StreamHandler()

    if debug:
        LOGGER.setLevel(logging.DEBUG)
    elif info:
        LOGGER.setLevel(logging.INFO)
    else:
        LOGGER.setLevel(logging.WARNING)
    log_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    ch.setFormatter(log_formatter)

    # make sure all other log handlers are removed before adding it back
    for handler in LOGGER.handlers:
        LOGGER.removeHandler(handler)
    LOGGER.addHandler(ch)


class CliArgs:
    """Base Args class."""

    def __init__(self, cli_args: Sequence[str] | None):
        self.parser = self.create_parser()
        self.cli_args = self.parser.parse_args(cli_args or [])

    def create_parser(self):
        parser = argparse.ArgumentParser(
            description="AWS Weighted Security Hub Finding Analyzer",
        )

        standard = parser.add_argument_group("Standard")
        advanced_weights = parser.add_argument_group("Advanced / Findings Weights")
        advanced = parser.add_argument_group("Advanced / Debugging")

        standard.add_argument(
            "-P",
            "--profile",
            action="store",
            default="default",
            help="AWS Profile to use",
        )
        standard.add_argument(
            "-Se",
            "--severities",
            action="store",
            nargs="+",
            choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            help='Findings to Include. Available options are "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL".',
        )

        standard.add_argument(
            "-S",
            "--standards",
            action="store",
            nargs="+",
            choices=["FSBP", "CIS12", "CIS14", "NIST80053R5", "PCI321"],
            default=["FSBP"],
            help='Standards to Include. Available options are "FSBP", "CIS12", "CIS14", "NIST80053R5", "PCI321".',
        )

        advanced_weights.add_argument(
            "-Wc",
            "--weight-critical",
            action="store",
            type=int,
            default=90,
            help="Weight for Critical Findings",
        )
        advanced_weights.add_argument(
            "-Wh",
            "--weight-high",
            action="store",
            type=int,
            default=70,
            help="Weight for High Findings",
        )
        advanced_weights.add_argument(
            "-Wm",
            "--weight-medium",
            action="store",
            type=int,
            default=40,
            help="Weight for Medium Findings",
        )
        advanced_weights.add_argument(
            "-Wl",
            "--weight-low",
            action="store",
            type=int,
            default=1,
            help="Weight for Low Findings",
        )
        advanced_weights.add_argument(
            "-Wi",
            "--weight-informational",
            action="store",
            type=int,
            default=0,
            help="Weight for Informational Findings",
        )

        ## Logging Settings
        logging_group = advanced.add_mutually_exclusive_group()

        logging_group.add_argument(
            "-I",
            "--info",
            action="store_true",
            help="Enables Info Level Logging",
        )
        logging_group.add_argument(
            "-D",
            "--debug",
            action="store_true",
            help="Enables Debug Level Logging",
        )

        return parser


class ConfigMixIn(CliArgs):
    def __init__(self, cli_args: list[str]):
        CliArgs.__init__(self, cli_args)

    def __repr__(self):
        return format_json_string(
            {
                "profile": self.profile,
                "severities": self.severities,
                "standards": self.standards,
                "weight_critical": self.weight_critical,
                "weight_high": self.weight_high,
                "weight_medium": self.weight_medium,
                "weight_low": self.weight_low,
                "weight_informational": self.weight_informational,
                "debug": self.debug,
                "info": self.info,
            },
        )

    def _get_argument_value(self, arg_name):
        return getattr(self.cli_args, arg_name)

    @property
    def profile(self):
        return self._get_argument_value("profile")

    @property
    def severities(self):
        return self._get_argument_value("severities")

    @property
    def standards(self):
        return self._get_argument_value("standards")

    @property
    def weight_critical(self):
        return self._get_argument_value("weight_critical")

    @property
    def weight_high(self):
        return self._get_argument_value("weight_high")

    @property
    def weight_medium(self):
        return self._get_argument_value("weight_medium")

    @property
    def weight_low(self):
        return self._get_argument_value("weight_low")

    @property
    def weight_informational(self):
        return self._get_argument_value("weight_informational")

    @property
    def debug(self):
        return self._get_argument_value("debug")

    @property
    def info(self):
        return self._get_argument_value("info")
