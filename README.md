# S3 Hook

This project creates an AWS Lambda function that sends logs from files stored in S3 bucket, to Logz.io

## Instructions:

To deploy this project, click the button that matches the region you wish to deploy your Stack to:

| Region           | Deployment                                                                                                                                                                                                                                                                                                                       |
|------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `us-east-1`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-us-east-1.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook)           | 
| `us-east-2`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-2#/stacks/create/review?templateURL=https://logzio-aws-integrations-us-east-2.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook)           | 
| `us-west-1`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-west-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-us-west-1.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook)           | 
| `us-west-2`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-west-2#/stacks/create/review?templateURL=https://logzio-aws-integrations-us-west-2.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook)           | 
| `eu-central-1`   | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-central-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-eu-central-1.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook)     | 
| `eu-north-1`     | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-north-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-eu-north-1.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook)         | 
| `eu-west-1`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-west-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-eu-west-1.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook)           | 
| `eu-west-2`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-west-2#/stacks/create/review?templateURL=https://logzio-aws-integrations-eu-west-2.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook)           | 
| `eu-west-3`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-west-3#/stacks/create/review?templateURL=https://logzio-aws-integrations-eu-west-3.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook)           | 
| `sa-east-1`      | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=sa-east-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-sa-east-1.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook)           | 
| `ap-northeast-1` | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-northeast-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-ap-northeast-1.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook) | 
| `ap-northeast-2` | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-northeast-2#/stacks/create/review?templateURL=https://logzio-aws-integrations-ap-northeast-2.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook) | 
| `ap-northeast-3` | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-northeast-3#/stacks/create/review?templateURL=https://logzio-aws-integrations-ap-northeast-3.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook) | 
| `ap-south-1`     | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-south-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-ap-south-1.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook)         | 
| `ap-southeast-1` | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-southeast-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-ap-southeast-1.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook) | 
| `ap-southeast-2` | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-southeast-2#/stacks/create/review?templateURL=https://logzio-aws-integrations-ap-southeast-2.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook) | 
| `ca-central-1`   | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ca-central-1#/stacks/create/review?templateURL=https://logzio-aws-integrations-ca-central-1.s3.amazonaws.com/s3-hook/0.1.0/sam-template.yaml&stackName=logzio-s3-hook)     | 


### 1. Specify stack details

Specify the stack details as per the table below, check the checkboxes and select **Create stack**.

| Parameter        | Description                                                                                                                                                                                                                                                         | Required/Default   |
|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------|
| `bucketName`     | Name of the bucket you wish to fetch logs from. Will be used for IAM policy.                                                                                                                                                                                        | **Required**       |
| `logzioListener` | The Logz.io listener URL for your region. (For more details, see the [regions page](https://docs.logz.io/user-guide/accounts/account-region.html)                                                                                                                   | **Required**       |
| `logzioToken`    | Your Logz.io log shipping token.                                                                                                                                                                                                                                    | **Required**       |
| `logLevel`       | Log level for the Lambda function. Can be one of: `debug`, `info`, `warn`, `error`, `fatal`, `panic`.                                                                                                                                                               | Default: `info`    |
| `logType`        | The log type you'll use with this Lambda. This is shown in your logs under the type field in Kibana. Logz.io applies parsing based on the log type.                                                                                                                 | Default: `s3_hook` |
| `pathsRegexes`   | Comma-seperated list of regexes that match the paths you'd like to pull logs from.                                                                                                                                                                                  | -                  |
| `pathToFields`   | Fields from the path to your logs directory that you want to add to the logs. For example, `org-id/aws-type/account-id` will add each of the fields `ord-id`, `was-type` and `account-id` to the logs that are fetched from the directory that this path refers to. | -                  |


### 3. Add trigger

Give the stack a few minutes to be deployed.

Once your Lambda function is ready, you'll need to manually add a trigger. This is due to Cloudformation limitations.

Go to the function's page, and click on **Add trigger**.

![Step 5 screenshot](img/05.png)

Then, choose **S3** as a trigger, and fill in:

- **Bucket**: Your bucket name.
- **Event type**: Choose option `All object create events`.
- Prefix and Suffix should be left empty.

Confirm the checkbox, and click **Add*.

![Step 5 screenshot](img/06.png)

### 3. Send logs

That's it. Your function is configured.
Once you upload new files to your bucket, it will trigger the function, and the logs will be sent to your Logz.io account.

#### Filtering files

If there are specific paths within the bucket that you want to pull logs from, you can use the `pathsRegex` variable.
This variable should hold a comma-seperated list of regexes that match the paths you wish to extract logs from.
**Note**: This will still trigger your Lambda function every time a new object is added to your bucket. However, if the key does not match the regexes, the function will quit and won't send the logs.


#### Adding object path as logs field

In case you want to use your objects' path as extra fields in your logs, you can do so by using `pathToFields`.

For example, if your objects are under the path: `oi-3rfEFA4/AWSLogs/2378194514/file.log`, where `oi-3rfEFA4` is org id, `AWSLogs` is aws type, and `2378194514` is account id. 

Setting `pathToFields` with the value: `org-id/aws-type/account-id` will add to logs the following fields:
`org-id`: `oi-3rfEFA4`, `aws-type`: `AWSLogs`, `account-id`: `2378194514`.

**Important notes about `pathToFields`**:

1. This will override a field with the same key, if it exists.
2. In order for the feature to work, you need to set `pathToFields` from the root of the bucket.

#### Control Tower support

If you want to ship Control Tower logs, after the deployment of the S3 Hook stack, you'll need to deploy an additional stack.
For more details [click here](https://github.com/logzio/s3-hook/tree/master/control_tower).

## Changelog

- **0.1.0**:
  - Add ability to filter paths with regex list in field `pathsRegexes`.
  - Add ability to map bucket path as log fields with `pathToFields`.
  - Add support for Control Tower.
- **0.0.2**:
  - **Bug fix**: Decodes folder names, for folders with special characters.
- **0.0.1**: Initial release.
