from boto3 import Session

PROFILE_NAME = "sec-prod-use1-admin"
AWS_ACCOUNT_ID = "984096407233"
BATCH_UPDATE_SIZE = 100

session = Session(profile_name=PROFILE_NAME)

client = session.client("securityhub")


findings: list = []

findings_filter = {
    "AwsAccountId": [
        {"Value": AWS_ACCOUNT_ID, "Comparison": "EQUALS"},
    ],
    "WorkflowStatus": [
        {"Value": "SUPPRESSED", "Comparison": "NOT_EQUALS"},
    ],
}
response = client.get_findings(
    Filters=findings_filter,
    MaxResults=100,
)
findings.extend(response["Findings"])

while "NextToken" in response:
    print(f"{len(findings)} findings found")

    response = client.get_findings(
        Filters=findings_filter,
        MaxResults=100,
        NextToken=response["NextToken"],
    )
    findings.extend(response["Findings"])


# for i in range(0, len(findings), BATCH_UPDATE_SIZE):
for i in range(0, 0, BATCH_UPDATE_SIZE):
    current_group = findings[i : i + BATCH_UPDATE_SIZE]

    update_group = []
    for j in current_group:
        update_group_entry = {
            "Id": j["Id"],
            "ProductArn": j["ProductArn"],
        }
        update_group.append(update_group_entry)

    response = client.batch_update_findings(
        FindingIdentifiers=update_group,
        Note={"Text": "Account Closure", "UpdatedBy": "Ryan Bowman"},
        Workflow={"Status": "SUPPRESSED"},
    )
