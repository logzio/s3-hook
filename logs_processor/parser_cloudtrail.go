package logs_processor

import (
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
)

func extractCloudtrailLogsFromFile(s3Log string, logger *zap.Logger) []string {
	var cloudtrailLogsJson map[string]interface{}
	logsToConvert := make([]string, 0)
	err := json.Unmarshal([]byte(s3Log), &cloudtrailLogsJson)
	if err != nil {
		logger.Error(fmt.Sprintf("error occurred while trying to marshal cloudtrail log: %s", err.Error()))
		logger.Error("will try to send as a regular string...")
		return []string{s3Log}
	} else {
		if records, ok := cloudtrailLogsJson[recordsField]; ok {
			for _, record := range records.([]interface{}) {
				tmpByteArr, _ := json.Marshal(record)
				logsToConvert = append(logsToConvert, string(tmpByteArr))
			}

			logger.Debug(fmt.Sprintf("found %d cloudtrail records", len(logsToConvert)))
			return logsToConvert
		} else {
			logger.Warn(fmt.Sprintf("could not find expected field %s in cloudtrail log. will send log as string", recordsField))
			return []string{s3Log}
		}
	}
}

func convertCloudtrailLogs(logzioLog map[string]interface{}, logToConvert string) error {
	var jsonLog map[string]interface{}
	err := json.Unmarshal([]byte(logToConvert), &jsonLog)
	if err != nil {
		logzioLog[fieldMessage] = logToConvert
		return err
	}

	for key, value := range jsonLog {
		logzioLog[key] = value
	}

	return nil
}
