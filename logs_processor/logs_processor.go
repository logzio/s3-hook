package logs_processor

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/s3"
	log "github.com/sirupsen/logrus"
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

func ProcessLogs(s3Object *s3.GetObjectOutput, logger *log.Entry, key, bucket, awsRegion string) [][]byte {
	logs := make([][]byte, 0)
	var logsStr string
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(s3Object.Body)

	if err != nil {
		logger.Errorf("Cannot proccess object %s. Error: %s", key, err.Error())
		return nil
	}

	logsStr = buf.String()
	contentType := strings.ToLower(*s3Object.ContentType)
	if strings.Contains(contentType, "zip") {
		logger.Debugf("Found a compressed file: %s", contentType)
		decompressed, err := decompressBody(buf, contentType, logger)
		if err != nil {
			logger.Errorf("Cannot decompress object %s. Error: %s", key, err.Error())
			return nil
		}

		logsStr = string(decompressed)
	}

	s3Logs := strings.Split(logsStr, "\n")
	for _, s3Log := range s3Logs {
		logBytes, err := convertToLogzioLog(s3Log, bucket, key, awsRegion, logger)
		if err != nil {
			continue
		}

		if logBytes != nil && len(logBytes) > 0 {
			logger.Debugf("Adding log %s to logs list", string(logBytes))
			logs = append(logs, logBytes)
		}
	}

	return logs
}

func decompressBody(buf *bytes.Buffer, contentType string, logger *log.Entry) ([]byte, error) {
	switch contentType {
	case "application/x-gzip":
		return decompressGzip(buf)
	default:
		return decompressZip(buf, logger)
	}
}

func decompressZip(buf *bytes.Buffer, logger *log.Entry) ([]byte, error) {
	var decompressed bytes.Buffer
	body, err := ioutil.ReadAll(buf)
	if err != nil {
		logger.Error(err)
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		logger.Error(err)
	}

	// Read all the files from zip archive
	for _, zipFile := range zipReader.File {
		unzippedFileBytes, err := readZipFile(zipFile)
		if err != nil {
			logger.Errorf("Encountered error while trying to read zip: %s", err.Error())
			continue
		}

		decompressed.Write(unzippedFileBytes)
		decompressed.Write([]byte("\n"))
	}

	logger.Debugf("Full decompressed:\n%s", string(decompressed.Bytes()))
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
	defer reader.Close()

	if err != nil {
		return nil, err
	}

	var decompressed bytes.Buffer
	_, err = decompressed.ReadFrom(reader)
	if err != nil {
		return nil, err
	}

	return decompressed.Bytes(), nil
}

func convertToLogzioLog(s3Log, bucket, key, awsRegion string, logger *log.Entry) ([]byte, error) {
	logger.Debugf("Converting log: %s", s3Log)
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
		logger.Errorf("Error occurred while processing %s: %s", objFullPath, err.Error())
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
