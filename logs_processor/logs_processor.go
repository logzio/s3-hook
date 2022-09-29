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
	"strings"
)

const (
	fieldType      = "type"
	fieldMessage   = "message"
	fieldS3Key     = "s3_object_key"
	fieldAwsRegion = "aws_region"
	defaultLogType = "s3_hook"
)

func ProcessLogs(s3Object *s3.GetObjectOutput, logger *zap.Logger, key, bucket, awsRegion string) [][]byte {
	logs := make([][]byte, 0)
	var logsToConvert []string
	var logsStr string
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(s3Object.Body)

	if err != nil {
		logger.Error(fmt.Sprintf("Cannot proccess object %s. Error: %s", key, err.Error()))
		return nil
	}

	controlTowerParsing := getControlTowerParsing()

	contentType := strings.ToLower(*s3Object.ContentType)
	logger.Debug(fmt.Sprintf("content type is: %s", contentType))
	logsStr = getBody(buf, logger)

	s3Logs := strings.Split(logsStr, "\n")
	keyLower := strings.ToLower(key)
	for _, s3Log := range s3Logs {
		if len(s3Log) == 0 {
			continue
		}

		// TODO: use a regex to make the decision making more accurate
		if strings.Contains(keyLower, cloudtrailName) {
			logsToConvert = extractCloudtrailLogsFromFile(s3Log, logger)
			logger.Debug(fmt.Sprintf("detected %s logs", cloudtrailName))
		} else {
			logsToConvert = []string{s3Log}
		}

		for _, logToConvert := range logsToConvert {
			logzioLog := make(map[string]interface{})
			if strings.Contains(keyLower, cloudtrailName) {
				err = convertCloudtrailLogs(logzioLog, logToConvert)
				if err != nil {
					logger.Error(fmt.Sprintf("error occurred while trying to create cloudtrail log: %s", err.Error()))
					logger.Error("will send log unparsed")
				}
				logger.Debug(fmt.Sprintf("converted %s log", cloudtrailName))
			} else {
				logzioLog[fieldMessage] = logToConvert
			}

			addLogzioFields(logzioLog, bucket, key, awsRegion)
			if len(controlTowerParsing) > 0 {
				addControlTowerParsing(controlTowerParsing, key, logzioLog, logger)
			}

			logBytes, err := json.Marshal(logzioLog)
			if err != nil {
				logger.Error(fmt.Sprintf("Error occurred while processing %s: %s", logToConvert, err.Error()))
				logger.Error("log will be dropped")
			}

			if logBytes != nil && len(logBytes) > 0 {
				logger.Debug(fmt.Sprintf("Adding log %s to logs list", string(logBytes)))
				logs = append(logs, logBytes)
			}
		}
	}

	return logs
}

func addLogzioFields(logzioLog map[string]interface{}, bucket, key, awsRegion string) {
	objFullPath := fmt.Sprintf("%s/%s", bucket, key)
	logzioLog[fieldType] = getLogType()
	logzioLog[fieldS3Key] = objFullPath
	logzioLog[fieldAwsRegion] = awsRegion
}

func getBody(buf *bytes.Buffer, logger *zap.Logger) string {
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

func addControlTowerParsing(controlTowerParsing, objectKey string, log map[string]interface{}, logger *zap.Logger) {
	parsingKeys := strings.Split(controlTowerParsing, "/")
	logger.Debug(fmt.Sprintf("received from user %d keys to add to log: %v", len(parsingKeys), parsingKeys))
	parsingValues := strings.Split(objectKey, "/")

	for index, pk := range parsingKeys {
		logger.Debug(fmt.Sprintf("Adding key: %s with value %s", pk, parsingValues[index]))
		log[pk] = parsingValues[index]
	}
}
