package main

import (
	"context"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	log "github.com/sirupsen/logrus"
	"main/logs_processor"
)

const (
	agentName = "s3_hook"
)

func HandleRequest(ctx context.Context, s3Event S3Event) {
	setLogLevel()
	logger := log.WithFields(log.Fields{"agent": agentName})
	logger.Info("Starting handling event...")
	logger.Debugf("Handling event: %+v", s3Event)
	logzioSender, err := getNewLogzioSender()
	defer logzioSender.Drain()
	if err != nil {
		logger.Errorf("Could not create logzio sender: %s. Exiting.", err.Error())
	}

	for _, record := range s3Event.Records {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(record.AwsRegion)},
		)

		if err != nil {
			logger.Errorf("Could not create session for bucket: %s, object: %s. Error: %s. This record will be skipped.",
				record.S3.Bucket.Name, record.S3.Object.Key, err.Error())
			continue
		}

		object, err := getObjectContent(sess, record.S3.Bucket.Name, record.S3.Object.Key)
		if err != nil {
			logger.Errorf("Could not fetch object %s from bucket %s. Error: %s. This record will be skipped.",
				record.S3.Object.Key, record.S3.Bucket.Name, err.Error())
			continue
		}
		logger.Debugf("Got object: %+v", object)

		logs := logs_processor.ProcessLogs(object, logger, record.S3.Object.Key, record.S3.Bucket.Name, record.AwsRegion)
		for _, log := range logs {
			_, err = logzioSender.Write(log)
			if err != nil {
				logger.Errorf("Encountered error while writing log %s to sender: %s", string(log), err.Error())
			}
		}
	}
}

func main() {
	lambda.Start(HandleRequest)
}

func setLogLevel() {
	logLevelStr := getHookLogLevel()
	logLevel, err := log.ParseLevel(logLevelStr)
	if err != nil {
		// if no error occurred while trying to parse the log level, we'll set the user's chosen log level.
		// otherwise, we'll use the logger's default log level (info)
		logLevel = log.InfoLevel
	}
	log.SetLevel(logLevel)
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
