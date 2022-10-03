package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/iam"
	l "github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
)

func createGetRolePolicyInput(roleName, policyName *string) *iam.GetRolePolicyInput {
	return &iam.GetRolePolicyInput{RoleName: roleName, PolicyName: policyName}
}

func createCreatePolicyInput(description, policyDocument, policyName *string) *iam.CreatePolicyInput {
	return &iam.CreatePolicyInput{
		Description:    description,
		PolicyDocument: policyDocument,
		PolicyName:     policyName,
	}
}

func createAttachRolePolicyInput(policyArn, roleName *string) *iam.AttachRolePolicyInput {
	return &iam.AttachRolePolicyInput{
		PolicyArn: policyArn,
		RoleName:  roleName,
	}
}

func createAddPermissionsInput(bucketName string, accountId, functionName *string) *l.AddPermissionInput {
	principal := "s3.amazonaws.com"
	statementId := fmt.Sprintf("bucket-invoke-%s", bucketName)
	bucketArn := fmt.Sprintf("arn:aws:s3:::%s", bucketName)
	action := "lambda:InvokeFunction"
	return &l.AddPermissionInput{
		Action:        &action,
		FunctionName:  functionName,
		Principal:     &principal,
		SourceAccount: accountId,
		SourceArn:     &bucketArn,
		StatementId:   &statementId,
	}
}

func createPutBucketNotificationConfigurationInput(bucketName, mainFuncArn string) *s3.PutBucketNotificationConfigurationInput {
	desiredEvent := "s3:ObjectCreated:*"
	lambdaConfig := s3.LambdaFunctionConfiguration{
		Events:            []*string{&desiredEvent},
		LambdaFunctionArn: &mainFuncArn,
	}
	notificationConfig := s3.NotificationConfiguration{
		LambdaFunctionConfigurations: []*s3.LambdaFunctionConfiguration{&lambdaConfig},
	}

	return &s3.PutBucketNotificationConfigurationInput{
		Bucket:                    &bucketName,
		NotificationConfiguration: &notificationConfig,
	}
}
