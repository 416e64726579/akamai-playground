package appsec

import (
	"context"
	"fmt"
	"net/http"
)

type (
	// Policy contains operations available on Security Configuration Policies resource
	// See: https://developer.akamai.com/api/cloud_security/application_security/v1.html#getsecuritypolicies
	Policy interface {
		// GetConfigs provides rules details namely actions
		// See: https://developer.akamai.com/api/cloud_security/application_security/v1.html#getsecuritypolicies
		GetPolicies(context.Context, int, int) (*GetPoliciesResponse, error)
	}

	// GetPoliciesResponse represents a security policies resource
	GetPoliciesResponse struct {
		ConfigID int         `json:"configId"`
		Version  int         `json:"version"`
		Policies []*Policies `json:"policies"`
	}

	// PolicySecurityControls represents an internal Security Control
	PolicySecurityControls struct {
		ApplyApplicationLayerControls bool `json:"applyApplicationLayerControls"`
		ApplyNetworkLayerControls     bool `json:"applyNetworkLayerControls"`
		ApplyRateControls             bool `json:"applyRateControls"`
		ApplyReputationControls       bool `json:"applyReputationControls"`
		ApplyBotmanControls           bool `json:"applyBotmanControls"`
		ApplyAPIConstraints           bool `json:"applyApiConstraints"`
		ApplySlowPostControls         bool `json:"applySlowPostControls"`
	}

	// Policies represents an internal policies structure
	Policies struct {
		PolicyID                string                 `json:"policyId"`
		PolicyName              string                 `json:"policyName"`
		HasRatePolicyWithAPIKey bool                   `json:"hasRatePolicyWithApiKey"`
		PolicySecurityControls  PolicySecurityControls `json:"policySecurityControls"`
	}
)

func (a *appsec) GetPolicies(ctx context.Context, configID, versionNumber int) (*GetPoliciesResponse, error) {
	var policies GetPoliciesResponse

	logger := a.Log(ctx)
	logger.Debug("GetConfigs")

	rulesURL := fmt.Sprintf("/appsec/v1/configs/%d/versions/%d/security-policies", configID, versionNumber)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rulesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create getconfigs request: %w", err)
	}

	// tools.CheckAccountID(req)

	resp, err := a.Exec(req, &policies)
	if err != nil {
		return nil, fmt.Errorf("getpolicies request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, a.Error(resp)
	}

	return &policies, nil
}
