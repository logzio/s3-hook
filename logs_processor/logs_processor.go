package logs_processor

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/s3"
	"go.uber.org/zap"
	"io"
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
	if strings.HasSuffix(strings.ToLower(key), ".txt") || strings.HasSuffix(strings.ToLower(key), ".log") {

		logs := make([][]byte, 0)
		var logsJsons []map[string]interface{}
		var logsStr string
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(s3Object.Body)

		if err != nil {
			logger.Error(fmt.Sprintf("Cannot proccess object %s. Error: %s", key, err.Error()))
			return nil
		}

		controlTowerParsing := getControlTowerParsing()

		logsStr = getBody(buf, logger)
		s3Logs := strings.Split(logsStr, "\n")
		keyLower := strings.ToLower(key)
		for _, s3Log := range s3Logs {
			if len(s3Log) == 0 {
				continue
			}

			if strings.Contains(keyLower, cloudtrailName) {
				logsJsons = extractCloudtrailLogsFromFile(s3Log, logger)
				logger.Debug(fmt.Sprintf("detected %s logs", cloudtrailName))
			} else {
				logsJsons = []map[string]interface{}{{fieldMessage: s3Log}}
			}

			for _, logJson := range logsJsons {
				addLogzioFields(logJson, bucket, key, awsRegion)
				if len(controlTowerParsing) > 0 {
					addControlTowerParsing(controlTowerParsing, key, logJson, logger)
				}

				logBytes, err := json.Marshal(logJson)
				if err != nil {
					logger.Error(fmt.Sprintf("Error occurred while processing %s: %s", logJson, err.Error()))
					logger.Error("log will be dropped")
				}

				if logBytes != nil && len(logBytes) > 0 {
					logger.Debug(fmt.Sprintf("Adding log %s to logs list", string(logBytes)))
					logs = append(logs, logBytes)
				}
			}
		}

		return logs
	} else if strings.HasSuffix(strings.ToLower(key), ".json") {
		// Read the JSON body into a byte slice using io.ReadAll.
		bodyBytes, err := io.ReadAll(s3Object.Body)
		if err != nil {
			logger.Error("Failed to read JSON body", zap.Error(err))
			return nil
		}
		// Ensure the body is closed after reading.
		defer func() {
			err := s3Object.Body.Close()
			if err != nil {
				// Handle the error or log it if necessary.
				logger.Error("Failed to close s3Object.Body", zap.Error(err))
			}
		}()

		// Prepare a buffer for the compacted JSON.
		var compactedBuffer bytes.Buffer

		// Use json.Compact to write the compacted JSON to the buffer.
		if err := json.Compact(&compactedBuffer, bodyBytes); err != nil {
			logger.Error("Failed to compact JSON", zap.Error(err))
			return nil
		}

		// Unmarshal the compacted JSON to a map for manipulation.
		var logJson map[string]interface{}
		if err := json.Unmarshal(compactedBuffer.Bytes(), &logJson); err != nil {
			logger.Error("Failed to unmarshal compacted JSON", zap.Error(err))
			return nil
		}

		// Apply the addLogzioFields function.
		addLogzioFields(logJson, bucket, key, awsRegion)

		// Marshal the modified map back to a byte slice.
		modifiedBytes, err := json.Marshal(logJson)
		if err != nil {
			logger.Error("Failed to marshal modified JSON", zap.Error(err))
			return nil
		}

		return [][]byte{modifiedBytes}
	} else {
		logger.Info(fmt.Sprintf("Ignoring unsupported file type for key: %s", key))
		return nil
	}
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
