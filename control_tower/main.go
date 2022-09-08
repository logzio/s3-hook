package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	l "github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"go.uber.org/zap"
	"strings"
)

func HandleRequest(ctx context.Context, ebEvent EventbridgeEvent) {
	// TODO: wrap each call to aws in retry
	// TODO: improve logs. specify bucket names where applicable
	// TODO: cleanup if a stage failed
	logger := getLogger()
	logger.Info("Starting handling event...")
	logger.Debug(fmt.Sprintf("Handling event: %+v", ebEvent))

	bucketName, awsRegion, mainFunctionArn, accountId := getTriggerDetails(ebEvent, logger)
	if len(bucketName) == 0 || len(awsRegion) == 0 || len(mainFunctionArn) == 0 {
		return
	}

	sess := getSession(awsRegion, logger)
	if sess == nil {
		return
	}

	err := manageBucketsPermissions(bucketName, mainFunctionArn, sess, logger)
	if err != nil {
		logger.Error(err.Error())
		return
	}

	err = addMainLambdaInvokePermission(bucketName, accountId, mainFunctionArn, sess, logger)
	if err != nil {
		logger.Error(err.Error())
		return
	}

	err = addNotificationConfiguration(bucketName, awsRegion, mainFunctionArn, sess, logger)
	if err != nil {
		logger.Error(err.Error())
		err = removePermissions(bucketName, mainFunctionArn, sess, logger)
		if err != nil {
			logger.Error(err.Error())
			return
		}

		return
	}

	logger.Info(fmt.Sprintf("Successfully added permissions and trigger to function %s and bucket %s", mainFunctionArn, bucketName))
}

func manageBucketsPermissions(bucketName string, mainFuncArn string, sess *session.Session, logger *zap.Logger) error {
	iamClient := iam.New(sess)
	if iamClient == nil {
		return fmt.Errorf("could not create IAM client. Aborting")
	}

	policyExists, err := isPolicyExists(iamClient, logger)
	if err != nil {
		return err
	}

	if !policyExists {
		err = grantBucketsPermission(iamClient, mainFuncArn, logger)
		if err != nil {
			return err
		}
	}

	return nil
}

func grantBucketsPermission(iamClient *iam.IAM, mainFuncArn string, logger *zap.Logger) error {
	policyArn, err := createPolicy(iamClient, logger)
	if err != nil {
		return err
	}

	err = attachPolicyToRole(iamClient, policyArn, logger)
	if err != nil {
		return err
	}

	return nil
}

func createPolicy(iamClient *iam.IAM, logger *zap.Logger) (*string, error) {
	policyName := getPolicyName()
	description := "Policy for allowing the function perform GetObject on created buckets"
	policyDocument := getPolicyDocumentBuckets()
	createPolicyReq := iam.CreatePolicyInput{
		Description:    &description,
		PolicyDocument: &policyDocument,
		PolicyName:     &policyName,
	}

	logger.Debug(fmt.Sprintf("request for create policy: %s", createPolicyReq.String()))
	createPolicyRes, err := iamClient.CreatePolicy(&createPolicyReq)
	if err != nil {
		return nil, fmt.Errorf("error occurred while trying to create policy: %s", err.Error())
	}

	if len(*createPolicyRes.Policy.Arn) == 0 {
		return nil, fmt.Errorf("call to create policy didn't retrieve an error, but no arn was retrieved")
	}

	logger.Debug(fmt.Sprintf("response from create policy: %s", createPolicyRes.String()))
	return createPolicyRes.Policy.Arn, nil
}

func attachPolicyToRole(iamClient *iam.IAM, policyArn *string, logger *zap.Logger) error {
	attachPolicyReq := createAttachPolicyRequest(policyArn)
	attachPolicyRes, err := iamClient.AttachRolePolicy(attachPolicyReq)
	policyName := getPolicyName()
	if err != nil {
		return fmt.Errorf("error occurred while trying to attach policy %s to role %s: %s", policyName, getRoleName(), err.Error())
	}

	logger.Debug(fmt.Sprintf("response from attach policy: %v", attachPolicyRes))
	return nil
}

func createAttachPolicyRequest(policyArn *string) *iam.AttachRolePolicyInput {
	roleName := getRoleName()
	return &iam.AttachRolePolicyInput{
		PolicyArn: policyArn,
		RoleName:  &roleName,
	}
}

func isPolicyExists(iamClient *iam.IAM, logger *zap.Logger) (bool, error) {
	roleName := getRoleName()
	logger.Debug(fmt.Sprintf("detected role name: %s", roleName))
	policyName := getPolicyName()
	logger.Debug(fmt.Sprintf("detected policy name: %s", policyName))
	logger.Debug("SHALOM 1")
	getPolicyReq := iam.GetRolePolicyInput{RoleName: &roleName, PolicyName: &policyName}
	_, err := iamClient.GetRolePolicy(&getPolicyReq)
	logger.Debug("SHALOM 2")
	if err != nil {
		if strings.Contains(err.Error(), "status code: 404") {
			logger.Info(fmt.Sprintf("could not find policy with name %s, will create a new one", policyName))
			return false, nil
		}

		return false, fmt.Errorf("error occurred while trying to get role policy for lambda function: %s", err.Error())
	}
	logger.Debug("SHALOM 3")

	logger.Info("s3-hook function contains required policy for buckets")
	return true, nil
}

func main() {
	lambda.Start(HandleRequest)
}

func getTriggerDetails(ebEvent EventbridgeEvent, logger *zap.Logger) (string, string, string, string) {
	bucketName := ebEvent.Detail.RequestParameters.BucketName
	if len(bucketName) == 0 {
		logger.Error("Could not find created bucket name. Aborting")
		return "", "", "", ""
	}

	awsRegion := ebEvent.Region
	if len(awsRegion) == 0 {
		logger.Error("Could not find aws region. Aborting")
		return "", "", "", ""

	}

	mainFunctionArn := getMainFunctionArn()
	if len(mainFunctionArn) == 0 {
		logger.Error(fmt.Sprintf("env var %s not specified. Aborting", envMainFunctionArn))
		return "", "", "", ""

	}

	accountId := getAccountId()
	if len(accountId) == 0 {
		logger.Error(fmt.Sprintf("env var %s not specified. Aborting", envAccountId))
		return "", "", "", ""
	}

	logger.Debug(fmt.Sprintf("detected bucket name: %s", bucketName))
	logger.Debug(fmt.Sprintf("detected aws region: %s", awsRegion))
	logger.Debug(fmt.Sprintf("detected main function arn: %s", mainFunctionArn))
	logger.Debug(fmt.Sprintf("detected account id: %s", accountId))

	return bucketName, awsRegion, mainFunctionArn, accountId
}

func getSession(awsRegion string, logger *zap.Logger) *session.Session {
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region: aws.String(awsRegion),
		},
	})

	if err != nil {
		logger.Error(fmt.Sprintf("error occurred while trying to create a connection to aws: %s. Aborting", err.Error()))
		return nil
	}

	return sess
}

func createBucketNotificationConfigInput(bucketName, mainFuncArn string) *s3.PutBucketNotificationConfigurationInput {
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

func addNotificationConfiguration(bucketName, awsRegion, mainFunctionArn string, sess *session.Session, logger *zap.Logger) error {
	s3Client := s3.New(sess)
	if s3Client == nil {
		return fmt.Errorf("could not create s3 client. Will delete the added lambda permision and abort")
	}

	bucketNotificationConfigInput := createBucketNotificationConfigInput(bucketName, mainFunctionArn)
	bucketNotificationConfigOutput, err := s3Client.PutBucketNotificationConfiguration(bucketNotificationConfigInput)
	if err != nil {
		return fmt.Errorf("error occurred while trying to add bucket notification configuration: %s", err.Error())
	}

	logger.Debug(fmt.Sprintf("resoponse from PutBucketNotificationConfiguration: %s", bucketNotificationConfigOutput.String()))
	return nil
}

func addMainLambdaInvokePermission(bucketName, accountId, mainFunctionArn string, sess *session.Session, logger *zap.Logger) error {
	lambdaClient := l.New(sess)
	if lambdaClient == nil {
		return fmt.Errorf("could not create lambda client. Aborting")
	}

	funcName := extractFuncNameFromArn(mainFunctionArn, logger)
	permReq := getAddPermissionsRequest(bucketName, accountId, funcName)
	permRes, err := lambdaClient.AddPermission(permReq)
	if err != nil {
		return fmt.Errorf("error occurred while trying to add permission to lambda function: %s", err.Error())
	}

	logger.Debug(fmt.Sprintf("response from AddPermission: %s", permRes.String()))
	return nil
}

func extractFuncNameFromArn(lambdaArn string, logger *zap.Logger) string {
	arnSlice := strings.Split(lambdaArn, ":")
	// Lambda function arn is in the following format: arn:<partition>:lambda:<region>:<accountId>:function:<funcName>
	funcName := arnSlice[len(arnSlice)-1]
	logger.Debug(fmt.Sprintf("extracted function name: %s from %s", funcName, lambdaArn))
	return funcName
}

func getAddPermissionsRequest(bucketName, accountId, functionName string) *l.AddPermissionInput {
	principal := "s3.amazonaws.com"
	statementId := fmt.Sprintf("bucket-invoke-%s", bucketName)
	bucketArn := fmt.Sprintf("arn:aws:s3:::%s", bucketName)
	action := "lambda:InvokeFunction"
	return &l.AddPermissionInput{
		Action:        &action,
		FunctionName:  &functionName,
		Principal:     &principal,
		SourceAccount: &accountId,
		SourceArn:     &bucketArn,
		StatementId:   &statementId,
	}
}

func getRemovePermissionsRequest(bucketName, functionName string) *l.RemovePermissionInput {
	statementId := fmt.Sprintf("bucket-invoke-%s", bucketName)
	return &l.RemovePermissionInput{
		FunctionName: &functionName,
		StatementId:  &statementId,
	}
}

func removePermissions(bucketName, mainFunctionArn string, sess *session.Session, logger *zap.Logger) error {
	lambdaClient := l.New(sess)
	if lambdaClient == nil {
		return fmt.Errorf("could not create lambda client. Aborting")
	}

	funcName := extractFuncNameFromArn(mainFunctionArn, logger)
	removePermReq := getRemovePermissionsRequest(bucketName, funcName)
	removePermRes, err := lambdaClient.RemovePermission(removePermReq)
	if err != nil {
		return fmt.Errorf("error occurred while trying to remove permissions: %s", err)
	}

	logger.Debug(fmt.Sprintf("response from RemovePermissions: %s", removePermRes.String()))
	return nil
}
