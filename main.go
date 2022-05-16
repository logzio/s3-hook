package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"main/logs_processor"
)

func HandleRequest(ctx context.Context, s3Event S3Event) {
	logger := getLogger()
	logger.Info("Starting handling event...")
	logger.Debug(fmt.Sprintf("Handling event: %+v", s3Event))
	logzioSender, err := getNewLogzioSender()
	defer logzioSender.Drain()
	if err != nil {
		logger.Error(fmt.Sprintf("Could not create logzio sender: %s. Exiting.", err.Error()))
	}

	for _, record := range s3Event.Records {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(record.AwsRegion)},
		)

		if err != nil {
			logger.Error(fmt.Sprintf("Could not create session for bucket: %s, object: %s. Error: %s. This record will be skipped.",
				record.S3.Bucket.Name, record.S3.Object.Key, err.Error()))
			continue
		}

		object, err := getObjectContent(sess, record.S3.Bucket.Name, record.S3.Object.Key)
		if err != nil {
			logger.Error(fmt.Sprintf("Could not fetch object %s from bucket %s. Error: %s. This record will be skipped.",
				record.S3.Object.Key, record.S3.Bucket.Name, err.Error()))
			continue
		}
		logger.Debug(fmt.Sprintf("Got object: %+v", object))

		logs := logs_processor.ProcessLogs(object, logger, record.S3.Object.Key, record.S3.Bucket.Name, record.AwsRegion)
		for _, log := range logs {
			_, err = logzioSender.Write(log)
			if err != nil {
				logger.Error(fmt.Sprintf("Encountered error while writing log %s to sender: %s", string(log), err.Error()))
			}
		}
	}
}

func main() {
	lambda.Start(HandleRequest)
}

func getObjectContent(sess *session.Session, bucketName, key string) (*s3.GetObjectOutput, error) {
	svc := s3.New(sess)
	getObjectInput := s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	}

	object, err := svc.GetObject(&getObjectInput)

	return object, err
}
