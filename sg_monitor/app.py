import os
import json
import requests

SAFE_PORTS = {22, 80, 443, 53, 3306}
TEAMS_WEBHOOK_URL = os.environ['TEAMS_WEBHOOK_URL']

# comment 5

def lambda_handler(event, context):
    print("🔔 Event received:")
    print(json.dumps(event, indent=2))

    detail = event.get("detail", {})
    request_parameters = detail.get("requestParameters", {})
    user_identity = detail.get("userIdentity", {})
    user_name = user_identity.get("userName", "Unknown")
    principal_id = user_identity.get("principalId", "Unknown")
    event_time = detail.get("eventTime", "Unknown")
    sg_id = request_parameters.get("groupId", "Unknown")

    ip_permissions = request_parameters.get("ipPermissions", {}).get("items", [])
    flagged_ports = set()

    for perm in ip_permissions:
        from_port = perm.get("fromPort", 0)
        to_port = perm.get("toPort", 65535)

        ip_ranges = perm.get("ipRanges", {}).get("items", [])
        for ip_range in ip_ranges:
            if ip_range.get("cidrIp") == "0.0.0.0/0":
                for port in range(from_port, to_port + 1):
                    if port not in SAFE_PORTS:
                        flagged_ports.add(port)

        ipv6_ranges = perm.get("ipv6Ranges", {}).get("items", [])
        for ip6 in ipv6_ranges:
            if ip6.get("cidrIpv6") == "::/0":
                for port in range(from_port, to_port + 1):
                    if port not in SAFE_PORTS:
                        flagged_ports.add(port)

    if flagged_ports:
        msg = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": "Security Group Alert",
            "themeColor": "FF0000",
            "title": "ALERT: SG with open access on unusual ports",
            "sections": [{
                "activityTitle": f"Security Group: {sg_id}",
                "facts": [
                    {"name": "Unusual Ports", "value": str(sorted(flagged_ports))},
                    {"name": "Modified By", "value": f"{user_name} ({principal_id})"},
                    {"name": "Time", "value": event_time},
                    {"name": "Recommendation", "value": "Restrict public access"}
                ],
                "markdown": True
            }]
        }
        requests.post(TEAMS_WEBHOOK_URL, json=msg)
        print("📨 Teams notification sent.")
    else:
        print("✅ No unusual open ports detected.")

    return {"statusCode": 200}
