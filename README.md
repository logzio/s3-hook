# S3 Hook

This project creates an AWS Lambda function that sends logs from files stored in S3 bucket, to Logz.io

## Instructions:

To deploy this project, click the button that matched the region you wish to deploy your Stack to:

| Region | Deployment                                                                                                                                                                                                                                                                                                               |
| --- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `us-east-1` | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/template?templateURL=https://logzio-aws-integrations-us-east-1.s3.amazonaws.com/s3_hook/0.0.1/sam-template.yaml&stackName=logzio-s3-hook) | 

### 1. Specify template

Keep the default setting in the Create stack screen and select **Next**.

<< TODO - 01 >>

### 2. Specify stack details

Specify the stack details as per the table below and select **Next**.

| Parameter        | Description                                                                                                                                       | Required/Default   |
|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|--------------------|
| `bucketName`     | Name of the bucket you wish to fetch logs from. Will be used for IAM policy.                                                                      | **Required**       |
| `logzioListener` | The Logz.io listener URL fot your region. (For more details, see the [regions page](https://docs.logz.io/user-guide/accounts/account-region.html) | **Required**       |
| `logzioToken`    | Your Logz.io log shipping token.                                                                                                                  | **Required**       |
| `logLevel`       | Log level for the Lambda function. Can be one of: `debug`, `info`, `warn`, `error`, `fatal`, `panic`.                                             | Default: `info`    |
| `logType`        | The log type you'll use with this Lambda. This is shown in your logs under the type field in Kibana. Logz.io applies parsing based on type.       | Default: `s3_hook` |


<< TODO - 02 >>

### 3. Configure stack options

Specify the Key and Value parameters for the Tags (optional) and select **Next**.

<< TODO - 03 >>

### 4. Review

Confirm that you acknowledge that AWS CloudFormation might create IAM resources and select **Create stack**.

<< TODO - 04 >>

### 5. Add trigger

Give the stack a few minutes to be deployed.

Once your Lambda function is ready, you'll need to manually add a trigger. This is due to Cloudformation limitations.

Go to the function's page, and click on **Add trigger**.

<< TODO - 05 >>

Then, choose **S3** as a trigger, and fill in:

- **Bucket**: Your bucket name.
- **Event type**: Choose option `All object create events`.
- Prefix and Suffix should be left empty.

Confirm the checkbox, and click **Add*.

<< TODO - 06 >>

### 6. Send logs

That's it. Your function is configured.
Once you'll upload new files to your bucket, it will trigger the function, and the logs will be sent to your Logz.io account.