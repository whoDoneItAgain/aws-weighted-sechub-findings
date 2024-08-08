import argparse
import configparser
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import boto3
import yaml

LOGGER = logging.getLogger("awsf")

CONTROL_NAME_MAPPINGS: dict = {
    "AWS Foundational Security Best Practices v1.0.0": "aws-foundational-security-best-practices/v/1.0.0",
    "CIS AWS Foundations Benchmark v1.2.0": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
    "CIS AWS Foundations Benchmark v1.4.0": "cis-aws-foundations-benchmark/v/1.4.0",
    "NIST Special Publication 800-53 Revision 5": "nist-800-53/v/5.0.0",
    "PCI DSS v3.2.1": "pci-dss/v/3.2.1",
}
STANDARDS_ARN_MAPPINGS: dict = {
    "AWS Foundational Security Best Practices v1.0.0": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0",
    "CIS AWS Foundations Benchmark v1.2.0": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
    "CIS AWS Foundations Benchmark v1.4.0": "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0",
    "NIST Special Publication 800-53 Revision 5": "arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0",
    "PCI DSS v3.2.1": "arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1",
}


def get_config_args():
    # Define the parser
    parser = argparse.ArgumentParser(description="AWS Weighted Sechub Findings")
    parser.add_argument(
        "--profile",
        action="store",
        type=str,
        default="sec-prod-use1-admin",
        help="Profile Name",
    )
    parser.add_argument(
        "--config-file",
        action="store",
        type=str,
        default="./config.yaml",
        help="Path to Configuration File",
    )
    parser.add_argument(
        "--aws-config-file",
        action="store",
        type=str,
        default="~/.aws/config",
        help="Path to Configuration File",
    )
    parser.add_argument(
        "--export-file",
        action="store",
        type=str,
        default="./outputs/weighted-findings.json",
        help="Path to Export File",
    )
    parser.add_argument(
        "--debug-logging",
        action="store_true",
        help="Enables Debug Level Logging",
    )
    parser.add_argument(
        "--info-logging",
        action="store_true",
        help="Enables Info Level Logging. Superseded by debug-logging",
    )

    args = parser.parse_args()

    return args


def configure_logging(debug_logging: bool = False, info_logging: bool = False):
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    if debug_logging:
        LOGGER.setLevel(logging.DEBUG)
    elif info_logging:
        LOGGER.setLevel(logging.INFO)
    else:
        LOGGER.setLevel(logging.NOTSET)
    log_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    ch.setFormatter(log_formatter)

    # make sure all other log handlers are removed before adding it back
    for handler in LOGGER.handlers:
        LOGGER.removeHandler(handler)
    LOGGER.addHandler(ch)


def main():
    assert sys.version_info >= (3, 12)

    config_args = get_config_args()

    configure_logging(
        debug_logging=config_args.debug_logging, info_logging=config_args.info_logging
    )

    LOGGER.debug(f"Configuration Arguments - {config_args}")

    aws_config_file = Path(os.path.expanduser(config_args.aws_config_file)).absolute()
    aws_profile: str = config_args.profile
    config_file = Path(config_args.config_file).absolute()
    export_file = Path(config_args.export_file).absolute()

    aws_config = configparser.RawConfigParser()
    aws_config.read(aws_config_file)

    with open(config_file, "r") as cf:
        config_settings: dict = yaml.safe_load(cf)

    LOGGER.debug(config_settings)

    included_controls: list = []
    for k, v in (config_settings["ControlsToInclude"]).items():
        if v:
            included_controls.append(k)
    included_severities: list = []
    for k, v in (config_settings["SeveritiesToInclude"]).items():
        if v:
            included_severities.append(k)

    # Start Build Severity Weight List
    SEVERITY_WEIGHTS: dict = {}
    if "SeverityWeight" in config_settings:
        SEVERITY_WEIGHTS.update(config_settings["SeverityWeight"])
    if "CRITICAL" not in SEVERITY_WEIGHTS:
        SEVERITY_WEIGHTS["CRITICAL"] = 90
    if "HIGH" not in SEVERITY_WEIGHTS:
        SEVERITY_WEIGHTS["HIGH"] = 70
    if "MEDIUM" not in SEVERITY_WEIGHTS:
        SEVERITY_WEIGHTS["MEDIUM"] = 40
    if "LOW" not in SEVERITY_WEIGHTS:
        SEVERITY_WEIGHTS["LOW"] = 1
    if "INFORMATIONAL" not in SEVERITY_WEIGHTS:
        SEVERITY_WEIGHTS["INFORMATIONAL"] = 0
    # End Build Severity Weight List

    LOGGER.debug(aws_config_file)
    LOGGER.debug(included_controls)
    LOGGER.debug(included_severities)
    LOGGER.debug(SEVERITY_WEIGHTS)
    LOGGER.debug(aws_config.sections())

    if not (aws_config.has_section(f"profile {aws_profile}")):
        raise Exception(
            f"AWS profile does not exist in aws config file: {aws_config_file}"
        )

    end_date = datetime.now() + timedelta(days=1)
    start_date = datetime.now() - timedelta(days=1)

    LOGGER.debug(start_date)
    LOGGER.debug(end_date)

    # Build Get Findings Filter - Generators
    filter_generator_list: list = []
    for ic in included_controls:
        filter_generator: dict = {}
        filter_generator["Value"] = CONTROL_NAME_MAPPINGS[ic]
        filter_generator["Comparison"] = "PREFIX"
        filter_generator_list.append(filter_generator)

    # Build Get Findings Filter - Severity
    filter_severity_list: list = []
    for insv in included_severities:
        filter_severity: dict = {}
        filter_severity["Value"] = insv
        filter_severity["Comparison"] = "EQUALS"
        filter_severity_list.append(filter_severity)

    # Build Get Findings Filter
    get_findings_filter: dict = {
        "GeneratorId": filter_generator_list,
        "SeverityLabel": filter_severity_list,
        "LastObservedAt": [
            {
                "End": end_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "Start": start_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        ],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    }

    LOGGER.debug(get_findings_filter)
    aws_session = boto3.Session(profile_name=aws_profile)
    sh_client = aws_session.client("securityhub")

    st = time.time()

    findings_results = sh_client.get_findings(
        Filters=get_findings_filter, MaxResults=100
    )
    sechub_findings = findings_results["Findings"]

    elapsed_time = time.strftime("%H:%M:%S", time.gmtime(time.time() - st))

    LOGGER.info(f"Findings Found: {len(sechub_findings)}. Elapsed Time: {elapsed_time}")
    while "NextToken" in findings_results:
        findings_results = sh_client.get_findings(
            Filters=get_findings_filter,
            MaxResults=100,
            NextToken=findings_results["NextToken"],
        )
        sechub_findings.extend(findings_results["Findings"])
        elapsed_time = time.strftime("%H:%M:%S", time.gmtime(time.time() - st))
        LOGGER.info(
            f"Findings Found: {len(sechub_findings)}. Elapsed Time: {elapsed_time}"
        )

    total_findings = len(sechub_findings)
    LOGGER.info(f"Total Findings: {total_findings}")

    (export_file.parent).mkdir(parents=True, exist_ok=True)

    # temp_list: list = []
    #
    # for f in sechub_findings:
    #    if f["Compliance"]["Status"] == "FAILED":
    #        temp_list.append(f)
    #
    # with open(export_file, "w") as ef:
    #    json.dump(temp_list, ef, indent=2)

    failed_findings: int = 0
    passed_findings: int = 0
    unknown_findings: int = 0

    # standard_subscription_arn = STANDARDS_ARN_MAPPINGS_MAPPINGS[]

    for f in sechub_findings:
        match f["Compliance"]["Status"]:
            case "PASSED":
                passed_findings += 1
            case "FAILED":
                failed_findings += 1
            case _:
                unknown_findings += 1

    LOGGER.info(f"Passed Findings: {passed_findings}")
    LOGGER.info(f"Failed Findings: {failed_findings}")
    LOGGER.info(f"Unknown Findings: {unknown_findings}")


if __name__ == "__main__":
    main()
