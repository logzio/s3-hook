package logs_processor

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	testBucketName = "test"
	testAwsRegion  = "us-east-1"
)

var (
	logger *log.Entry
)

func TestFileText(t *testing.T) {
	logType := "test-text-file"
	logger = setUpTest(logType)
	numberOfLogsInFile := 5
	fileName := "test.txt"
	contentType := "text/plain"
	s3GetObject := getS3OutputObject(fileName, contentType)
	logs := ProcessLogs(s3GetObject, logger, fileName, testBucketName, testAwsRegion)
	assert.NotNil(t, logs)
	assert.Equal(t, numberOfLogsInFile, len(logs))
	for index, logzioLog := range logs {
		var tmp map[string]interface{}
		err := json.Unmarshal(logzioLog, &tmp)
		assert.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("I AM A LOG FROM TXT FILE %d", index+1), tmp[fieldMessage])
		assert.Equal(t, logType, tmp[fieldType])
		assert.Equal(t, testAwsRegion, tmp[fieldAwsRegion])
		assert.Equal(t, fmt.Sprintf("%s/%s", testBucketName, fileName), tmp[fieldS3Key])
	}
}

func TestFileGzip(t *testing.T) {
	logType := "test-gzip-file"
	logger = setUpTest(logType)
	numberOfLogsInFile := 5
	fileName := "test.log.gz"
	contentType := "application/x-gzip"
	s3GetObject := getS3OutputObject(fileName, contentType)
	logs := ProcessLogs(s3GetObject, logger, fileName, testBucketName, testAwsRegion)
	assert.NotNil(t, logs)
	assert.Equal(t, numberOfLogsInFile, len(logs))
	for index, logzioLog := range logs {
		var tmp map[string]interface{}
		err := json.Unmarshal(logzioLog, &tmp)
		assert.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("I AM A LOG FROM GZIP FILE %d", index+1), tmp[fieldMessage])
		assert.Equal(t, logType, tmp[fieldType])
		assert.Equal(t, testAwsRegion, tmp[fieldAwsRegion])
		assert.Equal(t, fmt.Sprintf("%s/%s", testBucketName, fileName), tmp[fieldS3Key])
	}
}

func TestFileZip(t *testing.T) {
	logType := "test-zip-file"
	logger = setUpTest(logType)
	numberOfLogsTotal := 10
	numberOfLogsInFile := 5
	fileName := "test.zip"
	contentType := "application/zip"
	s3GetObject := getS3OutputObject(fileName, contentType)
	logs := ProcessLogs(s3GetObject, logger, fileName, testBucketName, testAwsRegion)
	assert.NotNil(t, logs)
	assert.Equal(t, numberOfLogsTotal, len(logs))
	for index, logzioLog := range logs {
		fileNum := 1
		logsIndex := index % numberOfLogsInFile
		if index >= numberOfLogsInFile {
			fileNum = 2
		}
		var tmp map[string]interface{}
		err := json.Unmarshal(logzioLog, &tmp)
		assert.NoError(t, err)
		assert.Equal(t, tmp[fieldMessage], fmt.Sprintf("I AM A LOG FROM COMPRESSED FILE #%d %d", fileNum, logsIndex+1))
		assert.Equal(t, logType, tmp[fieldType])
		assert.Equal(t, testAwsRegion, tmp[fieldAwsRegion])
		assert.Equal(t, fmt.Sprintf("%s/%s", testBucketName, fileName), tmp[fieldS3Key])
	}
}

func TestFileCSV(t *testing.T) {
	logType := "test-csv-file"
	logger = setUpTest(logType)
	numberOfLogs := 5
	fileName := "test.csv"
	contentType := "text/csv"
	s3GetObject := getS3OutputObject(fileName, contentType)
	logs := ProcessLogs(s3GetObject, logger, fileName, testBucketName, testAwsRegion)
	assert.NotNil(t, logs)
	assert.Equal(t, numberOfLogs, len(logs))
	for index, logzioLog := range logs {
		var tmp map[string]interface{}
		err := json.Unmarshal(logzioLog, &tmp)
		assert.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("THIS IS A LOG FROM CSV FILE %d,TEST_VAL %d", index+1, index+1), tmp[fieldMessage])
		assert.Equal(t, logType, tmp[fieldType])
		assert.Equal(t, testAwsRegion, tmp[fieldAwsRegion])
		assert.Equal(t, fmt.Sprintf("%s/%s", testBucketName, fileName), tmp[fieldS3Key])
	}
}

func TestFileJson(t *testing.T) {
	logType := "test-json-file"
	logger = setUpTest(logType)
	numberOfLogsInFile := 5
	fileName := "test.json"
	contentType := "application/json"
	s3GetObject := getS3OutputObject(fileName, contentType)
	logs := ProcessLogs(s3GetObject, logger, fileName, testBucketName, testAwsRegion)
	assert.NotNil(t, logs)
	for _, logzioLogs := range logs {
		var tmpLog map[string]interface{}
		err := json.Unmarshal(logzioLogs, &tmpLog)
		assert.NoError(t, err)
		assert.Equal(t, logType, tmpLog[fieldType])
		assert.Equal(t, testAwsRegion, tmpLog[fieldAwsRegion])
		assert.Equal(t, fmt.Sprintf("%s/%s", testBucketName, fileName), tmpLog[fieldS3Key])
		var actualLog []map[string]interface{}
		err = json.Unmarshal([]byte(tmpLog[fieldMessage].(string)), &actualLog)
		assert.NoError(t, err)
		assert.Equal(t, numberOfLogsInFile, len(actualLog))
		for index, logzioLog := range actualLog {
			assert.Equal(t, fmt.Sprintf("I AM A LOG FROM JSON FILE %d", index+1), logzioLog[fieldMessage])
		}
	}
}

func getLogFile(fileName string) string {
	b, err := os.ReadFile("test_logs/" + fileName)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func getS3OutputObject(fileName, contentType string) *s3.GetObjectOutput {
	testLog := getLogFile(fileName)
	body := io.NopCloser(strings.NewReader(testLog))
	contentLength := int64(len(testLog))
	obj := s3.GetObjectOutput{
		AcceptRanges:  aws.String("bytes"),
		Body:          body,
		ContentLength: aws.Int64(contentLength),
		ContentType:   aws.String(contentType),
		ETag:          aws.String("489ba84b67e12mde16c45c4160dk3b6c"),
		LastModified:  aws.Time(time.Now()),
	}

	return &obj
}

func setUpTest(logType string) *log.Entry {
	log.SetLevel(log.DebugLevel)
	logger = log.WithFields(log.Fields{"agent": "test"})
	os.Setenv(envLogType, logType)
	return logger
}
