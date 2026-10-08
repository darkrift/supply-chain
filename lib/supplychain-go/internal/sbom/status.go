package sbom

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type BuildStatus struct {
	Created      time.Time
	BuildVersion string
	GitCommit    string
	VCSRevision  string
	SerialNumber string
}

func ReadBuildStatus(paths ...string) (BuildStatus, error) {
	status := BuildStatus{Created: time.Unix(0, 0).UTC()}
	values := make(map[string]string)
	for _, path := range paths {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return BuildStatus{}, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			key, value, found := strings.Cut(line, " ")
			if !found {
				continue
			}
			values[key] = strings.TrimSpace(value)
		}
	}

	if timestamp := values["BUILD_TIMESTAMP"]; timestamp != "" {
		seconds, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			return BuildStatus{}, fmt.Errorf("parsing BUILD_TIMESTAMP %q: %w", timestamp, err)
		}
		status.Created = time.Unix(seconds, 0).UTC()
	}

	status.BuildVersion = values["STABLE_BUILD_VERSION"]
	status.GitCommit = values["STABLE_GIT_COMMIT"]
	status.VCSRevision = values["STABLE_VCS_REVISION"]
	status.SerialNumber = firstNonEmpty(values["STABLE_SBOM_SERIAL_NUMBER"], values["SBOM_SERIAL_NUMBER"])
	return status, nil
}

func (s BuildStatus) Version() string {
	return firstNonEmpty(s.BuildVersion, s.GitCommit, s.VCSRevision)
}

func (s BuildStatus) Revision() string {
	return firstNonEmpty(s.VCSRevision, s.GitCommit)
}

func (s BuildStatus) RevisionURL() string {
	revision := s.Revision()
	if revision == "" {
		return ""
	}
	if parsed, err := url.Parse(revision); err == nil && parsed.IsAbs() {
		return revision
	}
	return "urn:vcs:revision:" + url.PathEscape(revision)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
