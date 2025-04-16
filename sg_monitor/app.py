import os
import json
import requests

SAFE_PORTS = {22, 80, 443, 53, 3306}
TEAMS_WEBHOOK_URL = os.environ['TEAMS_WEBHOOK_URL']

def lambda_handler(event, context):
    print("🔔 Event received:")
    print(json.dumps(event, indent=2))

    request_parameters = event.get("detail", {}).get("requestParameters", {})
    ip_permissions = request_parameters.get("ipPermissions", {}).get("items", [])

    flagged_ports = []

    for perm in ip_permissions:
        from_port = perm.get("fromPort", 0)
        to_port = perm.get("toPort", 65535)

        ip_ranges = perm.get("ipRanges", {}).get("items", [])
        for ip_range in ip_ranges:
            if ip_range.get("cidrIp") == "0.0.0.0/0":
                for port in range(from_port, to_port + 1):
                    if port not in SAFE_PORTS:
                        print(f"🚨 Flagged port: {port}")
                        flagged_ports.append(port)

        ipv6_ranges = perm.get("ipv6Ranges", {}).get("items", [])
        for ip6 in ipv6_ranges:
            if ip6.get("cidrIpv6") == "::/0":
                for port in range(from_port, to_port + 1):
                    if port not in SAFE_PORTS:
                        print(f"🚨 Flagged IPv6 port: {port}")
                        flagged_ports.append(port)

    if flagged_ports:
        sg_id = request_parameters.get("groupId", "Unknown")
        msg = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": "Security Group Alert",
            "themeColor": "FF0000",
            "title": "ALERT: SG with open access on unusual ports",
            "sections": [{
                "activityTitle": f"Security Group: {sg_id}",
                "facts": [
                    {"name": "Unusual Ports", "value": str(sorted(set(flagged_ports)))},
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
