package appsec

import (
	"context"
	"fmt"
	"net/http"
)

type (
	// Rules contains operations available on Security Configuration Rules resource
	// See: https://developer.akamai.com/api/cloud_security/application_security/v1.html#getrules
	Rules interface {
		// GetConfigs provides rules details namely actions
		// See: https://developer.akamai.com/api/core_features/property_manager/v1.html#getgroups
		GetRules(context.Context, int, int, string) (*GetRulesResponse, error)
	}

	// GetRulesResponse represents a security rule resource
	GetRulesResponse struct {
		RuleActions []*RuleActions `json:"ruleActions"`
	}

	// RuleActions represents a specific rule details
	RuleActions struct {
		Action string `json:"action"`
		ID     int    `json:"id"`
	}
)

func (a *appsec) GetRules(ctx context.Context, configID, versionNumber int, policyID string) (*GetRulesResponse, error) {
	var rules GetRulesResponse

	logger := a.Log(ctx)
	logger.Debug("GetConfigs")

	rulesURL := fmt.Sprintf("/appsec/v1/configs/%d/versions/%d/security-policies/%s/rules", configID, versionNumber, policyID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rulesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create getconfigs request: %w", err)
	}

	// tools.CheckAccountID(req)

	resp, err := a.Exec(req, &rules)
	if err != nil {
		return nil, fmt.Errorf("getrules request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, a.Error(resp)
	}

	return &rules, nil
}
