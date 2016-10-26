audit CloudTrail
============================
This stack will monitor CloudTrail and alert on things CloudCoreo developers think are violations of best practices


## Description

This repo is designed to work with CloudCoreo. It will monitor CloudTrail against best practices for you and send a report to the email address designated by the config.yaml AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT value

## Variables Requiring Your Input

### `AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT`:
  * description: email recipient for notification

## Variables Required but Defaulted

### `AUDIT_AWS_CLOUDTRAIL_ALERT_LIST`:
  * description: alert list for generating notifications
  * default: cloudtrail-service-disabled

### `AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY`:
  * description: receive empty reports?

### `AUDIT_AWS_CLOUDTRAIL_PAYLOAD_TYPE`:
  * description: json or text
  * default: json

### `AUDIT_AWS_CLOUDTRAIL_SEND_ON`:
  * description: always or change
  * default: change

### `AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT`:
  * description: email recipient for notification

### `AUDIT_AWS_CLOUDTRAIL_REGIONS`:
  * description: list of AWS regions to check. Default is all regions
  * default: us-east-1,us-west-1,us-west-2

## Variables Not Required

**None**

## Tags

1. Audit
1. Best Practices
1. Alert
1. CloudTrail

## Categories

1. Audit

## Diagram



## Icon



