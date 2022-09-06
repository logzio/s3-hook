package main

import (
	"context"
	"encoding/json"
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

	err := editLambdaPermissionsPolicy(bucketName, mainFunctionArn, sess, logger)

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

func editLambdaPermissionsPolicy(bucketName, mainFuncArn string, sess *session.Session, logger *zap.Logger) error {
	iamClient := iam.New(sess)
	if iamClient == nil {
		return fmt.Errorf("could not create IAM client. Aborting")
	}

	policyDoc, err := getPolicyDocument(iamClient, logger)
	if err != nil {
		return err
	}

	logger.Debug(fmt.Sprintf("===========> %v", policyDoc))

	//newStatement := createStatement(mainFuncArn, bucketName)
	//logger.Debug(fmt.Sprintf("new statement: %v", newStatement))
	//policyDoc.Statement = append(policyDoc.Statement, newStatement)
	//policyDocStr, err := json.Marshal(policyDoc)
	//if err != nil {
	//	return fmt.Errorf("error occurred while trying to marshal policy doc: %s", err.Error())
	//}
	//
	//createPermPolicyVerReq := createPermissionPolicyVersionRequest(&policyDocStr)
	return nil
}

func createPermissionPolicyVersionRequest(policyDoc *string) *iam.CreatePolicyVersionInput {
	setAsDefault := true
	return &iam.CreatePolicyVersionInput{
		PolicyArn:      nil,
		PolicyDocument: policyDoc,
		SetAsDefault:   &setAsDefault,
	}
}

func createStatement(mainFuncArn, bucketName string) StatementObj {
	partitionIndex := 1
	arnSlice := strings.Split(mainFuncArn, ":")
	bucketArn := fmt.Sprintf("arn:%s:s3:::%s", arnSlice[partitionIndex], bucketName)

	return StatementObj{
		Action:   []string{"s3:GetObject"},
		Resource: []string{bucketArn},
		Effect:   "Allow",
	}
}

func getPolicyDocument(iamClient *iam.IAM, logger *zap.Logger) (PolicyDocument, error) {
	var policyDoc PolicyDocument
	roleName := getRoleName()
	policyName := getPolicyName()
	getPolicyReq := iam.GetRolePolicyInput{RoleName: &roleName, PolicyName: &policyName}
	getPolicyRes, err := iamClient.GetRolePolicy(&getPolicyReq)
	if getPolicyRes.PolicyName == nil {
		logger.Debug(fmt.Sprintf("could not find policy with name %s, will create a new one", policyName))
		// Todo - create new policy.
	}

	if err != nil {
		return policyDoc, fmt.Errorf("error occurred while trying to get role policy for lambda function: %s", err.Error())
	}

	err = json.Unmarshal([]byte(*getPolicyRes.PolicyDocument), &policyDoc)
	if err != nil {
		return policyDoc, fmt.Errorf("error occurred while trying to unmarshal policy document: %s", err.Error())
	}

	return policyDoc, nil
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
