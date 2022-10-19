package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	l "github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"go.uber.org/zap"
	"strings"
)

var (
	accountId string
	partition string
	funcName  string
)

func HandleRequest(ctx context.Context, ebEvent EventbridgeEvent) {
	logger := getLogger()
	logger.Info("Starting handling event...")
	logger.Debug(fmt.Sprintf("Handling event: %+v", ebEvent))

	bucketName, awsRegion, mainFunctionArn := getTriggerDetails(ebEvent, logger)
	if len(bucketName) == 0 || len(awsRegion) == 0 || len(mainFunctionArn) == 0 {
		return
	}

	extractInfoFromMainFuncArn(mainFunctionArn, logger)

	sess := getSession(awsRegion, logger)
	if sess == nil {
		return
	}

	err := addMainLambdaInvokePermission(bucketName, sess, logger)
	if err != nil {
		logger.Error(err.Error())
		return
	}

	err = addNotificationConfiguration(bucketName, mainFunctionArn, sess, logger)
	if err != nil {
		logger.Error(err.Error())
		return
	}

	logger.Info(fmt.Sprintf("Successfully added permissions and trigger to function %s and bucket %s", mainFunctionArn, bucketName))
}

func main() {
	lambda.Start(HandleRequest)
}

func getTriggerDetails(ebEvent EventbridgeEvent, logger *zap.Logger) (string, string, string) {
	bucketName := ebEvent.Detail.RequestParameters.BucketName
	if len(bucketName) == 0 {
		logger.Error("Could not find created bucket name. Aborting")
		return "", "", ""
	}

	awsRegion := ebEvent.Region
	if len(awsRegion) == 0 {
		logger.Error("Could not find aws region. Aborting")
		return "", "", ""

	}

	mainFunctionArn := getMainFunctionArn()
	if len(mainFunctionArn) == 0 {
		logger.Error(fmt.Sprintf("env var %s not specified. Aborting", envMainFunctionArn))
		return "", "", ""

	}

	logger.Debug(fmt.Sprintf("detected bucket name: %s", bucketName))
	logger.Debug(fmt.Sprintf("detected aws region: %s", awsRegion))
	logger.Debug(fmt.Sprintf("detected main function arn: %s", mainFunctionArn))

	return bucketName, awsRegion, mainFunctionArn
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

func addNotificationConfiguration(bucketName, mainFunctionArn string, sess *session.Session, logger *zap.Logger) error {
	s3Client := s3.New(sess)
	if s3Client == nil {
		return fmt.Errorf("could not create s3 client. Will delete the added lambda permision and abort")
	}

	bucketNotificationConfigInput := createPutBucketNotificationConfigurationInput(bucketName, mainFunctionArn)
	bucketNotificationConfigOutput, err := s3Client.PutBucketNotificationConfiguration(bucketNotificationConfigInput)
	if err != nil {
		return fmt.Errorf("error occurred while trying to add bucket notification configuration: %s", err.Error())
	}

	logger.Debug(fmt.Sprintf("resoponse from PutBucketNotificationConfiguration: %s", bucketNotificationConfigOutput.String()))
	return nil
}

func addMainLambdaInvokePermission(bucketName string, sess *session.Session, logger *zap.Logger) error {
	lambdaClient := l.New(sess)
	if lambdaClient == nil {
		return fmt.Errorf("could not create lambda client. Aborting")
	}

	permReq := createAddPermissionsInput(bucketName, &accountId, &funcName)
	permRes, err := lambdaClient.AddPermission(permReq)
	if err != nil {
		return fmt.Errorf("error occurred while trying to add permission to lambda function: %s", err.Error())
	}

	logger.Debug(fmt.Sprintf("response from AddPermission: %s", permRes.String()))
	return nil
}

func extractInfoFromMainFuncArn(mainFuncArn string, logger *zap.Logger) {
	// Lambda function arn is in the following format: arn:<partition>:lambda:<region>:<accountId>:function:<funcName>
	funcArnSlice := strings.Split(mainFuncArn, ":")
	partitionIndex := 1
	accountIdIndex := 4
	funcNameIndex := len(funcArnSlice) - 1
	partition = funcArnSlice[partitionIndex]
	logger.Info(fmt.Sprintf("using as partition: %s", partition))
	accountId = funcArnSlice[accountIdIndex]
	logger.Info(fmt.Sprintf("using as acocunt id: %s", accountId))
	funcName = funcArnSlice[funcNameIndex]
	logger.Info(fmt.Sprintf("using as s3 hook function name: %s", funcName))
	return
}
