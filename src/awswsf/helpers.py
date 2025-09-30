import json


def format_json_string(json_string):
    """Format the given JSON string."""
    return json.dumps(json_string, indent=1, sort_keys=True, separators=(",", ": "))
