package cloudaudit

import (
	"testing"
)

func TestNormalizeCloudAuditEvent(t *testing.T) {
	event, err := Normalize(AWS, []byte(`{"eventTime":"2026-01-02T03:04:05Z","userIdentity":{"arn":"arn:aws:iam::123:role/support"},"eventName":"PutItem","resource":"arn:aws:dynamodb:us-east-1:123:table/customers","errorCode":""}`))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if event.Action != "PutItem" || event.Resource == "" || !event.Success {
		t.Fatalf("unexpected event: %+v", event)
	}
}

func TestNormalizeRejectsUnsupportedAndIncomplete(t *testing.T) {
	if _, err := Normalize("oracle", []byte(`{}`)); err == nil {
		t.Fatal("unsupported provider accepted")
	}
	if _, err := Normalize(GCP, []byte(`{"timestamp":"2026-01-02T03:04:05Z"}`)); err == nil {
		t.Fatal("incomplete event accepted")
	}
}
