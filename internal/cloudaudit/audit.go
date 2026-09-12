package cloudaudit

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Provider string

const (
	AWS   Provider = "aws"
	GCP   Provider = "gcp"
	Azure Provider = "azure"
)

type Event struct {
	Timestamp   time.Time `json:"timestamp"`
	Provider    Provider  `json:"provider"`
	AgentID     string    `json:"agent_id,omitempty"`
	Principal   string    `json:"principal,omitempty"`
	Action      string    `json:"action"`
	Resource    string    `json:"resource"`
	Environment string    `json:"environment,omitempty"`
	Success     bool      `json:"success"`
}

type Options struct {
	MaxEvents    int
	MaxLineBytes int
}

func (o Options) withDefaults() Options {
	if o.MaxEvents <= 0 {
		o.MaxEvents = 1000000
	}
	if o.MaxLineBytes <= 0 {
		o.MaxLineBytes = 1 << 20
	}
	return o
}

func Normalize(provider Provider, payload []byte) (Event, error) {
	var value struct {
		Timestamp    string `json:"timestamp"`
		EventTime    string `json:"eventTime"`
		AgentID      string `json:"agent_id"`
		Principal    string `json:"principal"`
		UserIdentity struct {
			ARN   string `json:"arn"`
			Email string `json:"email"`
		} `json:"userIdentity"`
		Action       string `json:"action"`
		EventName    string `json:"eventName"`
		MethodName   string `json:"methodName"`
		Resource     string `json:"resource"`
		ResourceName string `json:"resourceName"`
		Environment  string `json:"environment"`
		Success      *bool  `json:"success"`
		ErrorCode    string `json:"errorCode"`
	}
	if err := json.Unmarshal(payload, &value); err != nil {
		return Event{}, fmt.Errorf("decode cloud audit event: %w", err)
	}
	if provider != AWS && provider != GCP && provider != Azure {
		return Event{}, fmt.Errorf("unsupported cloud provider %q", provider)
	}
	timestamp := value.Timestamp
	if timestamp == "" {
		timestamp = value.EventTime
	}
	parsed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return Event{}, fmt.Errorf("cloud audit timestamp: %w", err)
	}
	action := value.Action
	if action == "" {
		action = value.EventName
	}
	if action == "" {
		action = value.MethodName
	}
	resource := value.Resource
	if resource == "" {
		resource = value.ResourceName
	}
	if strings.TrimSpace(action) == "" || strings.TrimSpace(resource) == "" {
		return Event{}, fmt.Errorf("cloud audit action and resource are required")
	}
	principal := value.Principal
	if principal == "" {
		principal = value.UserIdentity.ARN
	}
	if principal == "" {
		principal = value.UserIdentity.Email
	}
	success := true
	if value.Success != nil {
		success = *value.Success
	}
	if value.ErrorCode != "" {
		success = false
	}
	return Event{Timestamp: parsed.UTC(), Provider: provider, AgentID: bounded(value.AgentID, 512), Principal: bounded(principal, 512), Action: bounded(action, 512), Resource: bounded(resource, 1024), Environment: bounded(value.Environment, 128), Success: success}, nil
}

func bounded(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) > max {
		return value[:max]
	}
	return value
}
