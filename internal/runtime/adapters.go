package runtime

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type Source string

const maxAdapterBytes = 64 << 20

const (
	SourceJSONL      Source = "jsonl"
	SourceOTelJSON   Source = "otel-json"
	SourceAPIGateway Source = "api-gateway"
)

func ReadSource(r io.Reader, source Source, options Options) ([]Event, int, error) {
	switch source {
	case "", SourceJSONL:
		return ReadEvents(r, options)
	case SourceOTelJSON:
		return readOTelJSON(r, options)
	case SourceAPIGateway:
		return readAPIGateway(r, options)
	default:
		return nil, 0, fmt.Errorf("unsupported runtime source %q", source)
	}
}

type otelDocument struct {
	ResourceSpans []otelResourceSpans `json:"resourceSpans"`
}

type otelResourceSpans struct {
	Resource   otelResource     `json:"resource"`
	ScopeSpans []otelScopeSpans `json:"scopeSpans"`
}

type otelScopeSpans struct {
	Spans []otelSpan `json:"spans"`
}

type otelResource struct {
	Attributes []otelAttribute `json:"attributes"`
}

type otelSpan struct {
	TraceID           string          `json:"traceId"`
	Name              string          `json:"name"`
	StartTimeUnixNano json.Number     `json:"startTimeUnixNano"`
	StartTime         string          `json:"startTime"`
	Status            otelStatus      `json:"status"`
	Attributes        []otelAttribute `json:"attributes"`
}

type otelStatus struct {
	Code string `json:"code"`
}

type otelAttribute struct {
	Key   string        `json:"key"`
	Value otelAttrValue `json:"value"`
}

type otelAttrValue struct {
	StringValue string      `json:"stringValue"`
	IntValue    json.Number `json:"intValue"`
	BoolValue   *bool       `json:"boolValue"`
}

func readOTelJSON(r io.Reader, options Options) ([]Event, int, error) {
	options = options.withDefaults()
	var document otelDocument
	decoder := json.NewDecoder(io.LimitReader(r, maxAdapterBytes))
	if err := decoder.Decode(&document); err != nil {
		return nil, 0, fmt.Errorf("decode OpenTelemetry JSON: %w", err)
	}
	events := make([]Event, 0)
	for _, resourceSpans := range document.ResourceSpans {
		resourceAttrs := attributes(resourceSpans.Resource.Attributes)
		for _, scopeSpans := range resourceSpans.ScopeSpans {
			for _, span := range scopeSpans.Spans {
				if len(events) >= options.MaxEvents {
					return nil, 0, fmt.Errorf("runtime event limit exceeded: %d", options.MaxEvents)
				}
				event, err := eventFromOTelSpan(span, resourceAttrs)
				if err != nil {
					return nil, 0, err
				}
				events = append(events, event)
			}
		}
	}
	return events, 0, nil
}

func eventFromOTelSpan(span otelSpan, resourceAttrs map[string]string) (Event, error) {
	attrs := attributes(span.Attributes)
	for key, value := range resourceAttrs {
		if _, exists := attrs[key]; !exists {
			attrs[key] = value
		}
	}
	timestamp, err := parseOTelTime(span.StartTime, span.StartTimeUnixNano)
	if err != nil {
		return Event{}, fmt.Errorf("decode OpenTelemetry span %q timestamp: %w", span.Name, err)
	}
	target := firstNonEmpty(attrs["agent.target"], attrs["tool.name"], attrs["rpc.method"], attrs["http.route"], attrs["server.address"], span.Name)
	operation := firstNonEmpty(attrs["agent.operation"], attrs["operation"], "trace:"+span.Name)
	success := !strings.EqualFold(span.Status.Code, "ERROR") && !strings.EqualFold(attrs["otel.status_code"], "ERROR")
	if statusCode, parseErr := strconv.Atoi(attrs["http.status_code"]); parseErr == nil && statusCode >= 400 {
		success = false
	}
	event := Event{
		Timestamp:   timestamp,
		RequestID:   firstNonEmpty(attrs["request.id"], attrs["http.request_id"], span.TraceID),
		AgentID:     firstNonEmpty(attrs["agent.id"], attrs["gen_ai.agent.id"]),
		AgentName:   firstNonEmpty(attrs["agent.name"], attrs["gen_ai.agent.name"]),
		Environment: firstNonEmpty(attrs["deployment.environment"], attrs["deployment.environment.name"]),
		Operation:   operation,
		Target:      target,
		Provider:    firstNonEmpty(attrs["gen_ai.system"], attrs["gen_ai.provider.name"], attrs["server.address"]),
		Action:      firstNonEmpty(attrs["agent.action"], attrs["tool.action"]),
		Success:     success,
	}
	if err := validateEvent(event); err != nil {
		return Event{}, fmt.Errorf("validate OpenTelemetry span %q: %w", span.Name, err)
	}
	return event, nil
}

func parseOTelTime(value string, unixNano json.Number) (time.Time, error) {
	if value != "" {
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return time.Time{}, err
		}
		return parsed, nil
	}
	nanos, err := strconv.ParseInt(string(unixNano), 10, 64)
	if err != nil || nanos <= 0 {
		return time.Time{}, fmt.Errorf("invalid startTimeUnixNano")
	}
	return time.Unix(0, nanos).UTC(), nil
}

func attributes(values []otelAttribute) map[string]string {
	result := make(map[string]string, len(values))
	for _, attribute := range values {
		value := attribute.Value.StringValue
		if value == "" {
			value = string(attribute.Value.IntValue)
		}
		if value == "" && attribute.Value.BoolValue != nil {
			value = strconv.FormatBool(*attribute.Value.BoolValue)
		}
		if attribute.Key != "" && value != "" {
			result[strings.ToLower(attribute.Key)] = value
		}
	}
	return result
}

type gatewayRecord struct {
	Timestamp   string `json:"timestamp"`
	RequestID   string `json:"request_id"`
	RequestID2  string `json:"requestId"`
	AgentID     string `json:"agent_id"`
	AgentID2    string `json:"agentId"`
	AgentName   string `json:"agent_name"`
	Environment string `json:"environment"`
	Operation   string `json:"operation"`
	Target      string `json:"target"`
	Provider    string `json:"provider"`
	Action      string `json:"action"`
	Success     *bool  `json:"success"`
	Status      string `json:"status"`
	StatusCode  int    `json:"status_code"`
}

func readAPIGateway(r io.Reader, options Options) ([]Event, int, error) {
	options = options.withDefaults()
	data, err := io.ReadAll(io.LimitReader(r, maxAdapterBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("read API Gateway events: %w", err)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, 0, nil
	}
	if data[0] == '[' {
		var records []gatewayRecord
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, 0, fmt.Errorf("decode API Gateway JSON: %w", err)
		}
		return gatewayEvents(records, options)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), options.MaxLineBytes)
	records := make([]gatewayRecord, 0)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var record gatewayRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, 0, fmt.Errorf("decode API Gateway JSONL event %d: %w", len(records)+1, err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("read API Gateway JSONL: %w", err)
	}
	return gatewayEvents(records, options)
}

func gatewayEvents(records []gatewayRecord, options Options) ([]Event, int, error) {
	if len(records) > options.MaxEvents {
		return nil, 0, fmt.Errorf("runtime event limit exceeded: %d", options.MaxEvents)
	}
	events := make([]Event, 0, len(records))
	for index, record := range records {
		timestamp, err := time.Parse(time.RFC3339Nano, record.Timestamp)
		if err != nil {
			return nil, 0, fmt.Errorf("decode API Gateway event %d timestamp: %w", index+1, err)
		}
		success := record.Success == nil || *record.Success
		if record.StatusCode >= 400 || strings.EqualFold(record.Status, "error") || strings.EqualFold(record.Status, "failed") {
			success = false
		}
		event := Event{Timestamp: timestamp, RequestID: firstNonEmpty(record.RequestID, record.RequestID2), AgentID: firstNonEmpty(record.AgentID, record.AgentID2), AgentName: record.AgentName, Environment: record.Environment, Operation: record.Operation, Target: record.Target, Provider: record.Provider, Action: record.Action, Success: success}
		if err := validateEvent(event); err != nil {
			return nil, 0, fmt.Errorf("validate API Gateway event %d: %w", index+1, err)
		}
		events = append(events, event)
	}
	return events, 0, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
