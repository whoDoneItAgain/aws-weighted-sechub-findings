import argparse
import configparser
import itertools
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


def configure_boto3_client(config_file, profile):

    aws_config = configparser.RawConfigParser()
    aws_config.read(config_file)

    if not (aws_config.has_section(f"profile {profile}")):
        raise Exception(f"AWS profile does not exist in aws config file: {config_file}")

    aws_session = boto3.Session(profile_name=profile)

    global SH_CLIENT
    SH_CLIENT = aws_session.client("securityhub")


def configure_settings(config_file):
    with open(config_file, "r") as cf:
        config_settings: dict = yaml.safe_load(cf)

    LOGGER.debug(config_settings)

    included_standards: list = []
    for k, v in (config_settings["StandardsToInclude"]).items():
        if v:
            included_standards.append(k)
    included_severities: list = []
    for k, v in (config_settings["SeveritiesToInclude"]).items():
        if v:
            included_severities.append(k)

    # Start Build Severity Weight List
    severity_weights: dict = {
        "CRITICAL": (
            config_settings["SeverityWeight"]["CRITICAL"]
            if "CRITICAL" in config_settings["SeverityWeight"]
            else 90
        ),
        "HIGH": (
            config_settings["SeverityWeight"]["HIGH"]
            if "HIGH" in config_settings["SeverityWeight"]
            else 70
        ),
        "MEDIUM": (
            config_settings["SeverityWeight"]["MEDIUM"]
            if "MEDIUM" in config_settings["SeverityWeight"]
            else 40
        ),
        "LOW": (
            config_settings["SeverityWeight"]["LOW"]
            if "LOW" in config_settings["SeverityWeight"]
            else 1
        ),
        "INFORMATIONAL": (
            config_settings["SeverityWeight"]["INFORMATIONAL"]
            if "INFORMATIONAL" in config_settings["SeverityWeight"]
            else 0
        ),
    }
    # End Build Severity Weight List

    return included_standards, included_severities, severity_weights


def get_disabled_controls(standard_arn: str) -> list[str]:

    # Get Standard Subscription Arn
    enabled_standards_response = SH_CLIENT.get_enabled_standards()
    enabled_standards_list: list = enabled_standards_response["StandardsSubscriptions"]
    while "NextToken" in enabled_standards_response:
        SH_CLIENT.get_enabled_standards(
            NextToken=enabled_standards_response["NextToken"]
        )

    for es in enabled_standards_list:
        if es["StandardsArn"] == standard_arn:
            standard_subscription_arn = es["StandardsSubscriptionArn"]
            break

    # Get Disabled Controls
    standard_controls_response = SH_CLIENT.describe_standards_controls(
        StandardsSubscriptionArn=standard_subscription_arn
    )
    standard_controls_list: list = standard_controls_response["Controls"]
    while "NextToken" in standard_controls_response:
        SH_CLIENT.describe_standards_controls(
            NextToken=standard_controls_response["NextToken"]
        )

    disabled_controls: list = []
    for sc in standard_controls_list:
        if sc["ControlStatus"] == "DISABLED":
            control_arn: str = sc["StandardsControlArn"]
            control_tail: str = control_arn.split(":control/")[1]
            disabled_controls.append(control_tail)

    LOGGER.info(f"Disabled Controls: {disabled_controls}")

    return disabled_controls


def get_findings(
    standard: str,
    severities: list[str],
    start_date: datetime,
    end_date: datetime,
    disabled_controls: list[str],
    severity_weights: dict[str, int],
):
    st = time.time()
    findings_results: dict = {}

    # Build Get Findings Filter - Severity
    filter_severity_list: list = []
    for insv in severities:
        filter_severity: dict = {}
        filter_severity["Value"] = insv
        filter_severity["Comparison"] = "EQUALS"
        filter_severity_list.append(filter_severity)

    # Build Get Findings Filter
    get_findings_filter: dict = {
        "GeneratorId": [{"Value": standard, "Comparison": "PREFIX"}],
        "SeverityLabel": filter_severity_list,
        "LastObservedAt": [
            {
                "End": end_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "Start": start_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        ],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    }

    LOGGER.debug(f"Findings Filter: {get_findings_filter}")
    # Build Get Findings Filter - End

    # Get Findings
    findings_results = SH_CLIENT.get_findings(
        Filters=get_findings_filter, MaxResults=100
    )
    sechub_findings = findings_results["Findings"]

    elapsed_time = time.strftime("%H:%M:%S", time.gmtime(time.time() - st))

    LOGGER.info(f"Findings Found: {len(sechub_findings)}. Elapsed Time: {elapsed_time}")

    while "NextToken" in findings_results:
        findings_results = SH_CLIENT.get_findings(
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
    findings_results["total_findings"] = total_findings
    LOGGER.info(f"Total Findings: {total_findings}")

    # Remove Disabled Controls
    enabled_sechub_findings: list = []
    for sf in sechub_findings:
        finding_standard_control_arn = sf["ProductFields"]["StandardsControlArn"]
        if not (finding_standard_control_arn.endswith(tuple(disabled_controls))):
            enabled_sechub_findings.append(sf)

    findings_results["enabled_findings"] = len(enabled_sechub_findings)
    LOGGER.info(f"Enabled Findings: {len(enabled_sechub_findings)}")

    # Calculate Findings my Control
    findings_by_control: dict[str, int] = {}
    for ef in enabled_sechub_findings:
        security_control_id = ef["Compliance"]["SecurityControlId"]
        if security_control_id in findings_by_control:
            findings_by_control[security_control_id] += 1
        else:
            findings_by_control[security_control_id] = 1

    # Calculate Findings my Severity
    findings_by_severity: dict[str, int] = {}
    findings_by_severity_original: dict[str, int] = {}
    for i, j in itertools.product(enabled_sechub_findings, severities):
        if i["Severity"]["Label"] == j:
            if j in findings_by_severity:
                findings_by_severity[j] += 1
            else:
                findings_by_severity[j] = 1
        if i["Severity"]["Original"] == j:
            if j in findings_by_severity_original:
                findings_by_severity_original[j] += 1
            else:
                findings_by_severity_original[j] = 1

    LOGGER.debug(findings_by_severity)
    LOGGER.debug(findings_by_severity_original)

    findings_by_severity_weighted: dict[str, int] = {}
    for k, v in findings_by_severity.items():
        findings_by_severity_weighted[k] = findings_by_severity[k] * severity_weights[k]

    LOGGER.debug(findings_by_severity_weighted)

    return findings_results


def main():
    assert sys.version_info >= (3, 12)

    config_args = get_config_args()

    configure_logging(
        debug_logging=config_args.debug_logging, info_logging=config_args.info_logging
    )

    LOGGER.debug(f"Configuration Arguments - {config_args}")

    configure_boto3_client(
        profile=config_args.profile,
        config_file=Path(os.path.expanduser(config_args.aws_config_file)).absolute(),
    )

    included_standards, included_severities, severity_weights = configure_settings(
        config_file=Path(config_args.config_file).absolute()
    )

    export_file = Path(config_args.export_file).absolute()

    LOGGER.info(f"Included Standards: {included_standards}")
    LOGGER.info(f"Included Severities: {included_severities}")
    LOGGER.info(f"Included Weights: {severity_weights}")

    end_date = datetime.now() + timedelta(days=1)
    start_date = datetime.now() - timedelta(days=1)

    LOGGER.info(f"Start Date: {start_date}")
    LOGGER.info(f"End Date: {end_date}")

    for ic in included_standards:
        disabled_controls = get_disabled_controls(
            standard_arn=STANDARDS_ARN_MAPPINGS[ic]
        )
        results = get_findings(
            standard=CONTROL_NAME_MAPPINGS[ic],
            severities=included_severities,
            start_date=start_date,
            end_date=end_date,
            disabled_controls=disabled_controls,
            severity_weights=severity_weights,
        )


if __name__ == "__main__":
    main()
