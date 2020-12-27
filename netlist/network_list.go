package netlist

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

// NetList represents a collection of Network Lists
//
// API Docs: // netlist v2
//
// https://developer.akamai.com/api/cloud_security/network_lists/v2.html

const (
	// IP is for IP based network lists
	IP NetworkType = iota + 1
	// GEO is for GEO location based network lists
	GEO
)

const (
	// STAGING is for STAGING environment
	STAGING Environment = iota + 1
	// PRODUCTION is for PRODUCTION environment
	PRODUCTION
)

func (n NetworkType) String() string {
	return [...]string{"IP", "GEO"}[n]
}

func (e Environment) String() string {
	return [...]string{"STAGING", "PRODUCTION"}[e-1]
}

type (
	// NetworkList contains operations available on NetworkList resource
	// See: // netlist v2
	//
	// https://developer.akamai.com/api/cloud_security/network_lists/v2.html#getlists
	NetworkList interface {
		ListNetworkLists(ctx context.Context, params ListNetworkListsRequest) (*ListNetworkListsResponse, error)
		GetNetworkList(ctx context.Context, params GetNetworkListRequest) (*NetworkListResponse, error)
		UpdateNetworkList(ctx context.Context, params UpdateNetworkListRequest) (*NetworkListResponse, error)
		CreateNetworkList(ctx context.Context, params CreateNetworkListRequest) (*NetworkListResponse, error)
		DeleteNetworkList(ctx context.Context, params DeleteNetworkListRequest) (*MessageNetworkList, error)
		AppendList(ctx context.Context, params AppendListRequest) (*NetworkListResponse, error)
		AddElement(ctx context.Context, params AddElementRequest) (*NetworkListResponse, error)
		RemoveElement(ctx context.Context, params RemoveElementRequest) (*NetworkListResponse, error)
		ActivateNetworkList(ctx context.Context, params ActivateNetworkListRequest) (*ActivationNetworkListResponse, error)
		GetActivationNetworkList(ctx context.Context, params ActivateNetworkListRequest) (*ActivationNetworkListResponse, error)
		GetActivationSnapshot(ctx context.Context, params GetActivationSnapshotRequest) (*NetworkListResponse, error)
		UpdateNetworkListDetails(ctx context.Context, params UpdateNetworkListDetailsRequest) error
	}

	// NetworkType represents type of a list (GEO or IP)
	// It is of enumeration type
	NetworkType int

	// Environment represents type of a list (STAGING or PRODUCTION)
	// It is of enumeration type
	Environment int

	// OptionalParams represents optional parameters for several calls
	OptionalParams struct {
		Extended        bool
		IncludeElements bool
	}

	// MessageNetworkList is a common object that responds to DELETE requests
	MessageNetworkList struct {
		Status   int    `json:"status"`
		Name     string `json:"name"`
		UniqueID string `json:"uniqueId"`
	}

	// ListNetworkListsRequest is a wrapper for List call
	ListNetworkListsRequest struct {
		*OptionalParams
		ListType NetworkType
		Search   string
	}

	// GetNetworkListRequest is a wrapper for getting a list
	GetNetworkListRequest struct {
		*OptionalParams
		NetworkListID string
	}

	// DeleteNetworkListRequest is a wrapper for list deletion
	DeleteNetworkListRequest struct {
		*GetNetworkListRequest
	}

	// UpdateNetworkListDetailsRequest is a wrapper for updating NL details
	UpdateNetworkListDetailsRequest struct {
		Name          string `json:"name"`
		Description   string `json:"description"`
		NetworkListID string
	}

	// ListNetworkListsResponse is a response of the fetching lists method
	ListNetworkListsResponse struct {
		NetworkLists []struct {
			*NetworkListResponse
		} `json:"networkLists"`
		Links struct {
			Create struct {
				Href   string `json:"href"`
				Method string `json:"method"`
			} `json:"create"`
		} `json:"links"`
	}

	// BodyNetworkListRequest is a JSON body for creating
	// and updating of a NL
	BodyNetworkListRequest struct {
		*GetNetworkListRequest
		Name        string   `json:"name"`
		Type        string   `json:"type"`
		Description string   `json:"description"`
		List        []string `json:"list"`
		ContractID  string   `json:"contractId,omitempty"`
		GroupID     int      `json:"groupId,omitempty"`
	}

	// CreateNetworkListRequest is a JSON body for creating of a NL
	CreateNetworkListRequest struct {
		*BodyNetworkListRequest
	}

	// UpdateNetworkListRequest is a JSON body for updating of a NL
	UpdateNetworkListRequest struct {
		*BodyNetworkListRequest
		SyncPoint int `json:"syncPoint"`
	}

	// NetworkListResponse encapsulates information about each network list
	NetworkListResponse struct {
		Name            string   `json:"name"`
		UniqueID        string   `json:"uniqueId"`
		SyncPoint       int      `json:"syncPoint"`
		Type            string   `json:"type"`
		NetworkListType string   `json:"networkListType"`
		ElementCount    int      `json:"elementCount"`
		ReadOnly        bool     `json:"readOnly"`
		Shared          bool     `json:"shared"`
		List            []string `json:"list"`
		Links           struct {
			ActivateInProduction struct {
				Href   string `json:"href"`
				Method string `json:"method"`
			} `json:"activateInProduction"`
			ActivateInStaging struct {
				Href   string `json:"href"`
				Method string `json:"method"`
			} `json:"activateInStaging"`
			AppendItems struct {
				Href   string `json:"href"`
				Method string `json:"method"`
			} `json:"appendItems"`
			Retrieve struct {
				Href string `json:"href"`
			} `json:"retrieve"`
			StatusInProduction struct {
				Href string `json:"href"`
			} `json:"statusInProduction"`
			StatusInStaging struct {
				Href string `json:"href"`
			} `json:"statusInStaging"`
			Update struct {
				Href   string `json:"href"`
				Method string `json:"method"`
			} `json:"update"`
		} `json:"links"`
	}

	// AppendListRequest contains a list of elements
	// to append to the list
	AppendListRequest struct {
		List          []string `json:"list"`
		NetworkListID string
	}

	// AddElementRequest contains an element to add to the list
	AddElementRequest struct {
		NetworkListID string
		Element       string
	}

	// RemoveElementRequest contains an element to remove from the list
	RemoveElementRequest struct {
		*AddElementRequest
	}

	// GetActivationSnapshotRequest contains information for snapshot request
	GetActivationSnapshotRequest struct {
		NetworkListID string
		Extended      bool
		SyncPoint     int
	}

	// ActivateNetworkListRequest is a wrapper for Activate call
	ActivateNetworkListRequest struct {
		NetworkListID          string
		Environment            Environment
		Comments               string   `json:"comments"`
		NotificationRecipients []string `json:"notificationRecipients"`
	}

	// ActivationNetworkListResponse represents an activation response
	ActivationNetworkListResponse struct {
		ActivationID       int    `json:"activationId"`
		ActivationComments string `json:"activationComments"`
		ActivationStatus   string `json:"activationStatus"`
		SyncPoint          int    `json:"syncPoint"`
		UniqueID           string `json:"uniqueId"`
		Fast               bool   `json:"fast"`
		DispatchCount      int    `json:"dispatchCount"`
		Links              struct {
			AppendItems struct {
				Href   string `json:"href"`
				Method string `json:"method"`
			} `json:"appendItems"`
			Retrieve struct {
				Href string `json:"href"`
			} `json:"retrieve"`
			StatusInProduction struct {
				Href string `json:"href"`
			} `json:"statusInProduction"`
			StatusInStaging struct {
				Href string `json:"href"`
			} `json:"statusInStaging"`
			SyncPointHistory struct {
				Href string `json:"href"`
			} `json:"syncPointHistory"`
			Update struct {
				Href   string `json:"href"`
				Method string `json:"method"`
			} `json:"update"`
			ActivationDetails struct {
				Href string `json:"href"`
			} `json:"activationDetails"`
		} `json:"links"`
	}
)

func (p *netlist) ListNetworkLists(ctx context.Context, params ListNetworkListsRequest) (*ListNetworkListsResponse, error) {

	logger := p.Log(ctx)
	logger.Debug("ListNetworkLists")

	var rval ListNetworkListsResponse

	uri := fmt.Sprintf(
		"/network-list/v2/network-lists",
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create listnetworklists request: %w", err)
	}

	q := req.URL.Query()

	q.Add("extended", strconv.FormatBool(params.Extended))
	q.Add("includeElements", strconv.FormatBool(params.IncludeElements))

	if params.Search != "" {
		q.Add("search", params.Search)
	}

	switch params.ListType {
	case IP:
		q.Add("listType", IP.String())
	case GEO:
		q.Add("listType", GEO.String())
	}
	req.URL.RawQuery = q.Encode()

	resp, err := p.Exec(req, &rval)
	if err != nil {
		return nil, fmt.Errorf("listnetworklists request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	return &rval, nil
}

func (p *netlist) GetNetworkList(ctx context.Context, params GetNetworkListRequest) (*NetworkListResponse, error) {
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStructValidation, err.Error())
	}

	logger := p.Log(ctx)
	logger.Debug("GetNetworkList")

	var rval NetworkListResponse

	uri := fmt.Sprintf(
		"/network-list/v2/network-lists/%s", params.NetworkListID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create getnetworklist request: %w", err)
	}

	q := req.URL.Query()
	q.Add("extended", strconv.FormatBool(params.Extended))
	q.Add("includeElements", strconv.FormatBool(params.IncludeElements))
	req.URL.RawQuery = q.Encode()

	resp, err := p.Exec(req, &rval)
	if err != nil {
		return nil, fmt.Errorf("getetworklist request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	return &rval, nil
}

func (p *netlist) UpdateNetworkList(ctx context.Context, params UpdateNetworkListRequest) (*NetworkListResponse, error) {
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStructValidation, err.Error())
	}

	logger := p.Log(ctx)
	logger.Debug("UpdateNetworkList")

	var rval NetworkListResponse

	uri := fmt.Sprintf(
		"/network-list/v2/network-lists/%s", params.NetworkListID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create updatenetworklist request: %w", err)
	}

	q := req.URL.Query()
	q.Add("extended", strconv.FormatBool(params.Extended))
	q.Add("includeElements", strconv.FormatBool(params.IncludeElements))
	req.URL.RawQuery = q.Encode()

	resp, err := p.Exec(req, &rval, params)
	if err != nil {
		return nil, fmt.Errorf("updatenetworklist request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	return &rval, nil
}

func (p *netlist) CreateNetworkList(ctx context.Context, params CreateNetworkListRequest) (*NetworkListResponse, error) {

	logger := p.Log(ctx)
	logger.Debug("CreateNetworkList")

	var rval NetworkListResponse

	uri := "/network-list/v2/network-lists"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create createnetworklist request: %w", err)
	}

	resp, err := p.Exec(req, &rval, params)
	if err != nil {
		return nil, fmt.Errorf("createnetworklist request failed: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, p.Error(resp)
	}

	return &rval, nil
}

func (p *netlist) DeleteNetworkList(ctx context.Context, params DeleteNetworkListRequest) (*MessageNetworkList, error) {
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStructValidation, err.Error())
	}

	logger := p.Log(ctx)
	logger.Debug("DeleteNetworkList")

	var rval MessageNetworkList

	uri := fmt.Sprintf(
		"/network-list/v2/network-lists/%s", params.NetworkListID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create deletenetworklist request: %w", err)
	}

	resp, err := p.Exec(req, &rval)
	if err != nil {
		return nil, fmt.Errorf("deletenetworklist request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	return &rval, nil
}

func (p *netlist) AppendList(ctx context.Context, params AppendListRequest) (*NetworkListResponse, error) {
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStructValidation, err.Error())
	}

	logger := p.Log(ctx)
	logger.Debug("AppendNetworkList")

	var rval NetworkListResponse

	uri := fmt.Sprintf(
		"/network-list/v2/network-lists/%s/append", params.NetworkListID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create appendnetworklist request: %w", err)
	}

	resp, err := p.Exec(req, &rval, params)
	if err != nil {
		return nil, fmt.Errorf("appendnetworklist request failed: %w", err)
	}

	if resp.StatusCode != http.StatusAccepted {
		return nil, p.Error(resp)
	}

	return &rval, nil
}

func (p *netlist) AddElement(ctx context.Context, params AddElementRequest) (*NetworkListResponse, error) {
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStructValidation, err.Error())
	}

	logger := p.Log(ctx)
	logger.Debug("AddElement")

	var rval NetworkListResponse

	uri := fmt.Sprintf(
		"/network-list/v2/network-lists/%s/elements", params.NetworkListID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create addelement request: %w", err)
	}

	q := req.URL.Query()
	q.Add("element", params.Element)
	req.URL.RawQuery = q.Encode()

	resp, err := p.Exec(req, &rval)
	if err != nil {
		return nil, fmt.Errorf("addelement request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	return &rval, nil
}

func (p *netlist) RemoveElement(ctx context.Context, params RemoveElementRequest) (*NetworkListResponse, error) {
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStructValidation, err.Error())
	}

	logger := p.Log(ctx)
	logger.Debug("RemoveElement")

	var rval NetworkListResponse

	uri := fmt.Sprintf(
		"/network-list/v2/network-lists/%s/elements", params.NetworkListID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create removeelement request: %w", err)
	}

	q := req.URL.Query()
	q.Add("element", params.Element)
	req.URL.RawQuery = q.Encode()

	resp, err := p.Exec(req, &rval)
	if err != nil {
		return nil, fmt.Errorf("removeelement request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	return &rval, nil
}

func (p *netlist) ActivateNetworkList(ctx context.Context, params ActivateNetworkListRequest) (*ActivationNetworkListResponse, error) {
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStructValidation, err.Error())
	}

	logger := p.Log(ctx)
	logger.Debug("ActivateNetworkLists")

	var rval ActivationNetworkListResponse

	uri := fmt.Sprintf(
		"/network-list/v2/network-lists/%s/environments/%s/activate", params.NetworkListID, params.Environment.String(),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create activatenetworklist request: %w", err)
	}

	resp, err := p.Exec(req, &rval, params)
	if err != nil {
		return nil, fmt.Errorf("activatenetworklist request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	return &rval, nil
}

func (p *netlist) GetActivationNetworkList(ctx context.Context, params ActivateNetworkListRequest) (*ActivationNetworkListResponse, error) {
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStructValidation, err.Error())
	}

	logger := p.Log(ctx)
	logger.Debug("GetActivationNetworkList")

	var rval ActivationNetworkListResponse

	uri := fmt.Sprintf(
		"/network-list/v2/network-lists/%s/environments/%s/status", params.NetworkListID, params.Environment.String(),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create getactivationnetworklist request: %w", err)
	}

	resp, err := p.Exec(req, &rval)
	if err != nil {
		return nil, fmt.Errorf("getactivationnetworklist request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	return &rval, nil
}

func (p *netlist) GetActivationSnapshot(ctx context.Context, params GetActivationSnapshotRequest) (*NetworkListResponse, error) {
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStructValidation, err.Error())
	}

	logger := p.Log(ctx)
	logger.Debug("GetActivationSnapshot")

	var rval NetworkListResponse

	uri := fmt.Sprintf(
		"/network-list/v2/network-lists/%s/sync-points/%d/history", params.NetworkListID, params.SyncPoint,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create getactivationsnapshot request: %w", err)
	}

	q := req.URL.Query()
	q.Add("extended", strconv.FormatBool(params.Extended))
	req.URL.RawQuery = q.Encode()

	resp, err := p.Exec(req, &rval)
	if err != nil {
		return nil, fmt.Errorf("getactivationsnapshot request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, p.Error(resp)
	}

	return &rval, nil
}

func (p *netlist) UpdateNetworkListDetails(ctx context.Context, params UpdateNetworkListDetailsRequest) error {
	if err := params.Validate(); err != nil {
		return fmt.Errorf("%w: %s", ErrStructValidation, err.Error())
	}

	logger := p.Log(ctx)
	logger.Debug("UpdateNetworkListDetails")

	uri := fmt.Sprintf(
		"/network-list/v2/network-lists/%s/details", params.NetworkListID,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uri, nil)
	if err != nil {
		return fmt.Errorf("failed to create updatenetworklistdetails request: %w", err)
	}

	resp, err := p.Exec(req, nil, params)
	if err != nil {
		return fmt.Errorf("updatenetworklistdetails request failed: %w", err)
	}

	if resp.StatusCode != http.StatusNoContent {
		return p.Error(resp)
	}

	return nil
}

// Validate validates GetNetworkListRequest
func (v GetNetworkListRequest) Validate() error {
	return validation.Errors{
		"networkListId": validation.Validate(v.NetworkListID, validation.Required),
	}.Filter()
}

// Validate validates UpdateNetworkListRequest
func (v UpdateNetworkListRequest) Validate() error {
	return validation.Errors{
		"networkListId": validation.Validate(v.GetNetworkListRequest.NetworkListID, validation.Required),
	}.Filter()
}

// Validate validates AppendListRequest
func (v AppendListRequest) Validate() error {
	return validation.Errors{
		"networkListId": validation.Validate(v.NetworkListID, validation.Required),
	}.Filter()
}

// Validate validates AddElementRequest
func (v AddElementRequest) Validate() error {
	return validation.Errors{
		"networkListId": validation.Validate(v.NetworkListID, validation.Required),
		"element":       validation.Validate(v.Element, validation.Required),
	}.Filter()
}

// Validate validates RemoveElementRequest
func (v RemoveElementRequest) Validate() error {
	return validation.Errors{
		"networkListId": validation.Validate(v.NetworkListID, validation.Required),
		"element":       validation.Validate(v.Element, validation.Required),
	}.Filter()
}

// Validate validates ActivateNetworkListRequest
func (v ActivateNetworkListRequest) Validate() error {
	return validation.Errors{
		"networkListId": validation.Validate(v.NetworkListID, validation.Required),
		"environment":   validation.Validate(v.Environment, validation.Required),
	}.Filter()
}

// Validate validates GetActivationSnapshotRequest
func (v GetActivationSnapshotRequest) Validate() error {
	return validation.Errors{
		"networkListId": validation.Validate(v.NetworkListID, validation.Required),
	}.Filter()
}

// Validate validates UpdateNetworkListRequest
func (v UpdateNetworkListDetailsRequest) Validate() error {
	return validation.Errors{
		"networkListId": validation.Validate(v.NetworkListID, validation.Required),
		"name":          validation.Validate(v.Name, validation.Required),
		"description":   validation.Validate(v.Description, validation.Required),
	}.Filter()
}
