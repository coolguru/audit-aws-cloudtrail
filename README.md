audit CloudTrail
============================
This stack will monitor CloudTrail and alert on things CloudCoreo developers think are violations of best practices


## Description
This repo is designed to work with CloudCoreo. It will monitor CloudTrail against best practices for you and send a report to the email address designated by the config.yaml AUDIT&#95;AWS&#95;CLOUDTRAIL&#95;ALERT&#95;RECIPIENT value


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-cloudtrail/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

**None**


## Required variables with default

### `AUDIT_AWS_CLOUDTRAIL_REGIONS`:
  * description: List of AWS regions to check. Default is all regions. Choices are us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,ap-south-1,ap-northeast-2,ap-southeast-1,ap-southeast-2,ap-northeast-1,eu-central-1,eu-west-1,eu-west-1,sa-east-1
  * default: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, ap-south-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-northeast-1, eu-central-1, eu-west-1, eu-west-2, sa-east-1

### `AUDIT_AWS_CLOUDTRAIL_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change

### `AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: false


## Optional variables with default

### `AUDIT_AWS_CLOUDTRAIL_ALERT_LIST`:
  * description: Which alerts would you like to check for? Default is all Cloudtrail alerts. Possible values are cloudtrail-service-disabled,cloudtrail-no-global-trails,cloudtrail-inventory, cloudtrail-log-file-validating
  * default: cloudtrail-service-disabled, cloudtrail-no-global-trails, cloudtrail-logs-cloudwatch

### `AUDIT_AWS_CLOUDTRAIL_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of the owner of the Cloudtrail object. (Optional)
  * default: NOT_A_TAG


## Optional variables with no default

### `AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.

## Tags
1. Audit
1. Best Practices
1. Alert
1. CloudTrail

## Categories
1. Audit



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-cloudtrail/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws-cloudtrail/master/images/icon.png "icon")


