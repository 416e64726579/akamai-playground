package appsec

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

type (
	// Configs contains operations available on Security Configuration resource
	// See: https://developer.akamai.com/api/cloud_security/application_security/v1.html#securityconfigurationsgroup
	Configs interface {
		// GetConfigs provides a read-only list of groups, which may contain properties.
		// See: https://developer.akamai.com/api/core_features/property_manager/v1.html#getgroups
		GetConfigs(context.Context) (*GetConfigsResponse, error)
	}

	// ConfigVersions contains operations available on Security Configuration Versions resource
	// See: https://developer.akamai.com/api/cloud_security/application_security/v1.html#getsummarylistofconfigurationversions
	ConfigVersions interface {
		GetConfigVersions(context.Context, int, ...string) (*GetConfigVersionsResponse, error)
	}

	// Config represents a property config resource
	Config struct {
		ID                  int      `json:"id"`
		LatestVersion       int      `json:"latestVersion"`
		Name                string   `json:"name"`
		Description         string   `json:"description,omitempty"`
		ProductionVersion   int      `json:"productionVersion,omitempty"`
		StagingVersion      int      `json:"stagingVersion,omitempty"`
		ProductionHostnames []string `json:"productionHostnames,omitempty"`
	}

	// ConfigItems represents sub-compent of the config response
	ConfigItems struct {
		Configs []*Config `json:"configurations"`
	}

	// GetConfigsResponse represents a collection of configs
	// This is the reponse to the /appsec/v1/configs request
	GetConfigsResponse struct {
		ConfigItems
	}

	// GetConfigVersionsResponse represents a collection of config versions
	// This is the reponse to the /appsec/v1/configs/{configId}/versions{?page,pageSize,detail} request
	GetConfigVersionsResponse struct {
		TotalSize                   int            `json:"totalSize"`
		PageSize                    int            `json:"pageSize"`
		Page                        int            `json:"page"`
		ConfigID                    int            `json:"configId"`
		ConfigName                  string         `json:"configName"`
		StagingExpediteRequestID    int            `json:"stagingExpediteRequestId"`
		ProductionExpediteRequestID int            `json:"productionExpediteRequestId"`
		ProductionActiveVersion     int            `json:"productionActiveVersion"`
		StagingActiveVersion        int            `json:"stagingActiveVersion"`
		LastCreatedVersion          int            `json:"lastCreatedVersion"`
		VersionList                 []*VersionList `json:"versionList"`
	}

	// Production represents a status of production environment for version
	Production struct {
		Status string    `json:"status"`
		Time   time.Time `json:"time,-"`
	}

	// Staging represents a status of production environment for version
	Staging struct {
		Status string    `json:"status"`
		Time   time.Time `json:"time,-"`
	}

	// VersionList represents a list of version details
	VersionList struct {
		Version      int        `json:"version"`
		VersionNotes string     `json:"versionNotes"`
		CreateDate   time.Time  `json:"createDate"`
		CreatedBy    string     `json:"createdBy"`
		BasedOn      int        `json:"basedOn,omitempty"`
		Production   Production `json:"production,omitempty"`
		Staging      Staging    `json:"staging,omitempty"`
	}
)

func (a *appsec) GetConfigs(ctx context.Context) (*GetConfigsResponse, error) {
	var configs GetConfigsResponse

	logger := a.Log(ctx)
	logger.Debug("GetConfigs")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/appsec/v1/configs", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create getconfigs request: %w", err)
	}

	// tools.CheckAccountID(req)

	resp, err := a.Exec(req, &configs)
	if err != nil {
		return nil, fmt.Errorf("getconfigs request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, a.Error(resp)
	}

	return &configs, nil
}

// GetConfigVersions accepts required configID, optional accountID and params:
// 1. page (integer in string representation) The number of items on each result page. The default value is 25.
// 2. pageSize (integer in string representation) The index of the result page. If the value is -1,
// then pagination is ignored. The default value is 1.
// 3. Detail (boolean in string representation) When true, the results contain detailed information
// on versions. When false, the results contain summary information on versions.
func (a *appsec) GetConfigVersions(ctx context.Context, configID int, params ...string) (*GetConfigVersionsResponse, error) {
	var configVersions GetConfigVersionsResponse

	logger := a.Log(ctx)
	logger.Debug("GetConfigVersions")

	var configVersionsURL string
	switch len(params) {
	case 1:
		configVersionsURL = fmt.Sprintf(
			"/appsec/v1/configs/%d/versions?detail=%s", configID, params[0])
	case 2:
		configVersionsURL = fmt.Sprintf(
			"/appsec/v1/configs/%d/versions?page=%s&pageSize=%s", configID, params[0], params[1])
	case 3:
		configVersionsURL = fmt.Sprintf(
			"/appsec/v1/configs/%d/versions?page=%s&pageSize=%s&detail=%s", configID, params[0], params[1], params[2])
	default:
		configVersionsURL = fmt.Sprintf(
			"/appsec/v1/configs/%d/versions?page=%d&pageSize=%d&detail=%s", configID, 1, 25, "true")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configVersionsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create getconfigversions request: %w", err)
	}

	// tools.CheckAccountID(req)

	resp, err := a.Exec(req, &configVersions)
	if err != nil {
		return nil, fmt.Errorf("getconfigversions request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, a.Error(resp)
	}

	return &configVersions, nil
}
