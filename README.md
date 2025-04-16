
# SG Monitor - AWS SAM Project

This project sets up an automated alert system using AWS Lambda and EventBridge to detect when a Security Group allows open access (0.0.0.0/0) on unusual ports and notifies you via Microsoft Teams.

## ✅ What This Does

- Monitors `AuthorizeSecurityGroupIngress` API calls via CloudTrail/EventBridge
- Triggers a Lambda function that checks for insecure rules
- Sends alerts to a Microsoft Teams channel via webhook

## 📁 Folder Structure

```
sg-monitor-sam/
├── template.yaml               # SAM template
└── sg_monitor/
    ├── app.py                  # Lambda handler
    └── requirements.txt        # Python dependencies
```

## 🚀 Deployment Instructions

### 1. Prerequisites

- AWS CLI configured
- AWS SAM CLI installed: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html
- Microsoft Teams webhook URL created

### 2. Build and Deploy

Run this from the root of the project directory:

```bash
sam build
sam deploy --guided
```

You’ll be prompted to:

- **Stack Name**: e.g., `sg-monitor-prod`
- **AWS Region**: e.g., `ap-south-1`
- **TEAMSWebhook**: Paste your Teams Incoming Webhook URL
- Confirm and save the `samconfig.toml`

### 3. Reuse Configured Deploy

After the first deploy, just run:

```bash
sam deploy
```

### 4. Optional: Pass Webhook Without Prompt

```bash
sam deploy   --stack-name sg-monitor-prod   --region ap-south-1   --parameter-overrides TEAMSWebhook=https://outlook.office.com/webhook/YOUR-WEBHOOK   --capabilities CAPABILITY_IAM
```

### 5. Save Webhook to `samconfig.toml` for automation

```toml
[default.deploy.parameters]
parameter_overrides = "TEAMSWebhook=https://outlook.office.com/webhook/YOUR-WEBHOOK"
```

## 💡 Customize Safe Ports

Edit `SAFE_PORTS` in `app.py` to define which ports are allowed publicly:
```python
SAFE_PORTS = {22, 80, 443, 53, 3306}
```

## 📬 Output

Alerts will appear in your Microsoft Teams channel with details about:

- Security Group ID
- Unsafe open ports
- Recommendation to restrict access
- User who made the change
- Timestamp of the event
