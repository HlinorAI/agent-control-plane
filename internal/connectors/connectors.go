package connectors

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Kind string

const (
	GitHub     Kind = "github"
	GitLab     Kind = "gitlab"
	Docker     Kind = "docker"
	Kubernetes Kind = "kubernetes"
)

type Source struct {
	Kind    Kind   `json:"kind"`
	Name    string `json:"name"`
	Locator string `json:"locator"`
}
type Metadata struct {
	Source      Source            `json:"source"`
	Repository  string            `json:"repository,omitempty"`
	Project     string            `json:"project,omitempty"`
	Image       string            `json:"image,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	Workload    string            `json:"workload,omitempty"`
	Revision    string            `json:"revision,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type Connector interface {
	Kind() Kind
	Normalize([]byte) (Metadata, error)
}

type Registry struct{ connectors map[Kind]Connector }

func NewRegistry() Registry {
	return Registry{connectors: map[Kind]Connector{GitHub: githubConnector{}, GitLab: gitlabConnector{}, Docker: dockerConnector{}, Kubernetes: kubernetesConnector{}}}
}
func (r Registry) Normalize(kind Kind, payload []byte) (Metadata, error) {
	connector, ok := r.connectors[kind]
	if !ok {
		return Metadata{}, fmt.Errorf("unsupported connector %q", kind)
	}
	return connector.Normalize(payload)
}

func normalizeString(value string, max int) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) > max {
		return "", fmt.Errorf("metadata value exceeds %d bytes", max)
	}
	return value, nil
}
func normalizeMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && len(key) <= 256 && len(value) <= 1024 && !sensitiveKey(key) && !sensitiveKey(value) {
			result[key] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func sensitiveKey(value string) bool {
	normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(value))
	for _, part := range []string{"secret", "token", "password", "apikey", "authorization", "credential"} {
		if strings.Contains(normalized, part) {
			return true
		}
	}
	return false
}

func decode(data []byte, target any) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("decode connector metadata: %w", err)
	}
	if len(raw) == 0 {
		return fmt.Errorf("connector metadata must be a JSON object")
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode connector metadata: %w", err)
	}
	return nil
}

type githubConnector struct{}

func (githubConnector) Kind() Kind { return GitHub }
func (githubConnector) Normalize(data []byte) (Metadata, error) {
	var value struct {
		FullName      string   `json:"full_name"`
		Name          string   `json:"name"`
		HTMLURL       string   `json:"html_url"`
		DefaultBranch string   `json:"default_branch"`
		Topics        []string `json:"topics"`
	}
	if err := decode(data, &value); err != nil {
		return Metadata{}, err
	}
	repo, err := normalizeString(value.FullName, 512)
	if err != nil {
		return Metadata{}, err
	}
	if repo == "" {
		repo, err = normalizeString(value.Name, 512)
		if err != nil {
			return Metadata{}, err
		}
	}
	locator, err := normalizeString(value.HTMLURL, 1024)
	if err != nil {
		return Metadata{}, err
	}
	revision, err := normalizeString(value.DefaultBranch, 128)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{Source: Source{Kind: GitHub, Name: "GitHub repository", Locator: locator}, Repository: repo, Revision: revision, Labels: normalizeMap(mapFromList(value.Topics))}, nil
}

type gitlabConnector struct{}

func (gitlabConnector) Kind() Kind { return GitLab }
func (gitlabConnector) Normalize(data []byte) (Metadata, error) {
	var value struct {
		PathWithNamespace string   `json:"path_with_namespace"`
		Name              string   `json:"name"`
		WebURL            string   `json:"web_url"`
		DefaultBranch     string   `json:"default_branch"`
		Topics            []string `json:"topics"`
	}
	if err := decode(data, &value); err != nil {
		return Metadata{}, err
	}
	project, err := normalizeString(value.PathWithNamespace, 512)
	if err != nil {
		return Metadata{}, err
	}
	if project == "" {
		project, err = normalizeString(value.Name, 512)
		if err != nil {
			return Metadata{}, err
		}
	}
	locator, err := normalizeString(value.WebURL, 1024)
	if err != nil {
		return Metadata{}, err
	}
	revision, err := normalizeString(value.DefaultBranch, 128)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{Source: Source{Kind: GitLab, Name: "GitLab project", Locator: locator}, Project: project, Revision: revision, Labels: normalizeMap(mapFromList(value.Topics))}, nil
}

type dockerConnector struct{}

func (dockerConnector) Kind() Kind { return Docker }
func (dockerConnector) Normalize(data []byte) (Metadata, error) {
	var value struct {
		RepoTags []string `json:"RepoTags"`
		Config   struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := decode(data, &value); err != nil {
		return Metadata{}, err
	}
	image := ""
	if len(value.RepoTags) > 0 {
		image = value.RepoTags[0]
	}
	image, err := normalizeString(image, 1024)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{Source: Source{Kind: Docker, Name: "Docker image", Locator: image}, Image: image, Labels: normalizeMap(value.Config.Labels)}, nil
}

type kubernetesConnector struct{}

func (kubernetesConnector) Kind() Kind { return Kubernetes }
func (kubernetesConnector) Normalize(data []byte) (Metadata, error) {
	var value struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name        string            `json:"name"`
			Namespace   string            `json:"namespace"`
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := decode(data, &value); err != nil {
		return Metadata{}, err
	}
	workload, err := normalizeString(value.Metadata.Name, 512)
	if err != nil {
		return Metadata{}, err
	}
	namespace, err := normalizeString(value.Metadata.Namespace, 256)
	if err != nil {
		return Metadata{}, err
	}
	kind, err := normalizeString(value.Kind, 128)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{Source: Source{Kind: Kubernetes, Name: kind + " workload", Locator: namespace + "/" + workload}, Namespace: namespace, Workload: workload, Labels: normalizeMap(value.Metadata.Labels), Annotations: normalizeMap(value.Metadata.Annotations)}, nil
}

func mapFromList(values []string) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result[value] = "true"
		}
	}
	return result
}
