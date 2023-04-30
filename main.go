package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"go.uber.org/zap"
	"main/logs_processor"
	"main/paths_filter"
	"net/url"
	"strings"
)

func HandleRequest(ctx context.Context, s3Event S3Event) {
	logger := getLogger()
	logger.Info("Starting handling event...")
	logger.Debug(fmt.Sprintf("Handling event: %+v", s3Event))
	logzioSender, err := getNewLogzioSender()
	pathsToInclude := getIncludePathsRegex()
	pathsToExclude := getExcludePathsRegex()
	defer logzioSender.Drain()
	if err != nil {
		logger.Error(fmt.Sprintf("Could not create logzio sender: %s. Exiting.", err.Error()))
	}

	for _, record := range s3Event.Records {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(record.AwsRegion)},
		)

		key := decodeKey(logger, record.S3.Object.Key)
		if err != nil {
			logger.Error(fmt.Sprintf("Could not create session for bucket: %s, object: %s. Error: %s. This record will be skipped.",
				record.S3.Bucket.Name, key, err.Error()))
			continue
		}

		if pathsToInclude != nil && pathsToExclude != nil {
					logger.Error(fmt.Sprintf("Include and exclude are mutually exclusive. Cannot use both. Exiting"))
					break
		}

		if pathsToInclude != nil {
			if !paths_filter.IsFilterPath(key, pathsToInclude, logger) {
				logger.Info(fmt.Sprintf("Key %s does not match any of the include paths %v. Skipping it.", key, pathsToInclude))
				continue
			}
		}

		if pathsToExclude != nil {
			if paths_filter.IsFilterPath(key, pathsToExclude, logger) {
				logger.Info(fmt.Sprintf("Key %s matches to one of the exclude paths %v. Excluding path.", key, pathsToExclude))
				continue
			}
		}

		object, err := getObjectContent(sess, record.S3.Bucket.Name, key)
		if err != nil {
			logger.Error(fmt.Sprintf("Could not fetch object %s from bucket %s. Error: %s. This record will be skipped.",
				key, record.S3.Bucket.Name, err.Error()))
			continue
		}
		logger.Debug(fmt.Sprintf("Got object: %+v", object))

		logs := logs_processor.ProcessLogs(object, logger, key, record.S3.Bucket.Name, record.AwsRegion)
		for _, log := range logs {
			_, err = logzioSender.Write(log)
			logzioSender.Drain()
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

func decodeKey(logger *zap.Logger, key string) string {
	decodedKey, err := url.QueryUnescape(key)
	if err != nil {
		logger.Error(fmt.Sprintf("error occurred while trying to unescape the key: %s. Reverting to original key.", err.Error()))
		return key
	}

	if strings.ToLower(key) != strings.ToLower(decodedKey) {
		logger.Debug(fmt.Sprintf("Decoded object key from: %s, to %s", key, decodedKey))
	}

	return decodedKey
}
