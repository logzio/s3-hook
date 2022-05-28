package logs_processor

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/s3"
	"go.uber.org/zap"
	"io/ioutil"
	"os"
	"strings"
)

const (
	fieldType      = "type"
	fieldMessage   = "message"
	fieldS3Key     = "s3_object_key"
	fieldAwsRegion = "aws_region"
	defaultLogType = "s3_hook"
	envLogType     = "LOG_TYPE"
)

func ProcessLogs(s3Object *s3.GetObjectOutput, logger *zap.Logger, key, bucket, awsRegion string) [][]byte {
	logs := make([][]byte, 0)
	var logsStr string
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(s3Object.Body)

	if err != nil {
		logger.Error(fmt.Sprintf("Cannot proccess object %s. Error: %s", key, err.Error()))
		return nil
	}

	contentType := strings.ToLower(*s3Object.ContentType)
	logger.Debug(fmt.Sprintf("content type is: %s", contentType))
	logsStr = getBody(buf, contentType, logger)

	s3Logs := strings.Split(logsStr, "\n")
	for _, s3Log := range s3Logs {
		logBytes, err := convertToLogzioLog(s3Log, bucket, key, awsRegion, logger)
		if err != nil {
			continue
		}

		if logBytes != nil && len(logBytes) > 0 {
			logger.Debug(fmt.Sprintf("Adding log %s to logs list", string(logBytes)))
			logs = append(logs, logBytes)
		}
	}

	return logs
}

func getBody(buf *bytes.Buffer, contentType string, logger *zap.Logger) string {
	// Try to decompress Gzip:
	tempBuf := *buf
	body, err := decompressGzip(&tempBuf)
	if err == nil {
		logger.Debug("body was Gzipped!")
		return string(body)
	}

	logger.Debug(fmt.Sprintf("Error from attempt to decompress gzip: %s", err.Error()))
	// Try to decompress Zip:
	tempBuf = *buf
	body, err = decompressZip(&tempBuf, logger)
	if err == nil {
		logger.Debug("body was Zipped!")
		return string(body)
	}
	logger.Debug(fmt.Sprintf("Error from attempt to decompress zip: %s", err.Error()))

	// Returning string as is
	logger.Debug("Could not decompress gzip or zip, returning the body as is")
	return buf.String()
}

func decompressZip(buf *bytes.Buffer, logger *zap.Logger) ([]byte, error) {
	var decompressed bytes.Buffer
	body, err := ioutil.ReadAll(buf)
	if err != nil {
		return nil, err
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, err
	}

	// Read all the files from zip archive
	for _, zipFile := range zipReader.File {
		unzippedFileBytes, err := readZipFile(zipFile)
		if err != nil {
			logger.Error(fmt.Sprintf("Encountered error while trying to read zip: %s", err.Error()))
			continue
		}

		decompressed.Write(unzippedFileBytes)
		decompressed.Write([]byte("\n"))
	}

	logger.Debug(fmt.Sprintf("Full decompressed:\n%s", string(decompressed.Bytes())))
	return decompressed.Bytes(), nil
}

func readZipFile(zf *zip.File) ([]byte, error) {
	f, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ioutil.ReadAll(f)
}

func decompressGzip(buf *bytes.Buffer) ([]byte, error) {
	reader, err := gzip.NewReader(buf)

	if err != nil {
		return nil, err
	}

	defer reader.Close()

	var decompressed bytes.Buffer
	_, err = decompressed.ReadFrom(reader)
	if err != nil {
		return nil, err
	}

	return decompressed.Bytes(), nil
}

func convertToLogzioLog(s3Log, bucket, key, awsRegion string, logger *zap.Logger) ([]byte, error) {
	logger.Debug(fmt.Sprintf("Converting log: %s", s3Log))
	if len(s3Log) == 0 {
		return nil, nil
	}
	objFullPath := fmt.Sprintf("%s/%s", bucket, key)
	logzioLog := make(map[string]interface{})
	logzioLog[fieldType] = getLogType()
	logzioLog[fieldS3Key] = objFullPath
	logzioLog[fieldAwsRegion] = awsRegion
	logzioLog[fieldMessage] = s3Log

	logBytes, err := json.Marshal(logzioLog)
	if err != nil {
		logger.Error(fmt.Sprintf("Error occurred while processing %s: %s", objFullPath, err.Error()))
	}

	return logBytes, err
}

func getLogType() string {
	logType := os.Getenv(envLogType)
	if len(logType) == 0 {
		logType = defaultLogType
	}

	return logType
}
