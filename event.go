package main

type S3Event struct {
	Records []RecordObj `json:"Records"`
}

type RecordObj struct {
	EventVersion      string               `json:"eventVersion"`
	EventSource       string               `json:"eventSource"`
	AwsRegion         string               `json:"awsRegion"`
	EventTime         string               `json:"eventTime"`
	EventName         string               `json:"eventName"`
	UserIdentity      UserIdentityObj      `json:"userIdentity"`
	RequestParameters RequestParametersObj `json:"requestParameters"`
	ResponseElements  ResponseElementsObj  `json:"responseElements"`
	S3                S3Obj                `json:"s3"`
}

type UserIdentityObj struct {
	PrincipalId string `json:"principalId"`
}

type RequestParametersObj struct {
	SourceIPAddress string `json:"sourceIPAddress"`
}

type ResponseElementsObj struct {
	XAmzRequestId string `json:"x-amz-request-id"`
	XAmzId2       string `json:"x-amz-id-2"`
}

type S3Obj struct {
	S3SchemaVersion string    `json:"s3SchemaVersion"`
	ConfigurationId string    `json:"configurationId"`
	Bucket          BucketObj `json:"bucket"`
	Object          ObjectObj `json:"object"`
}

type BucketObj struct {
	Name          string           `json:"name"`
	OwnerIdentity OwnerIdentityObj `json:"ownerIdentity"`
	Arn           string           `json:"arn"`
}

type OwnerIdentityObj struct {
	PrincipalId string `json:"principalId"`
}

type ObjectObj struct {
	Key       string  `json:"key"`
	Size      float32 `json:"size"`
	ETag      string  `json:"eTag"`
	Sequencer string  `json:"sequencer"`
}
