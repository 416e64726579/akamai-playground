package main

import (
	"context"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/test-go/appsec"
	"github.com/test-go/netlist"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v2/pkg/edgegrid"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v2/pkg/papi"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v2/pkg/session"
	"github.com/apex/log"
	"github.com/apex/log/handlers/text"
)

// ContractParams represents optional parameters when creating a NL
type ContractParams struct {
	ContractID string
	GroupID    int
}

// NewContractParams returns an initialized ContractParams struct with passed values
func NewContractParams(contractID string, groupID int) ContractParams {
	return ContractParams{ContractID: contractID, GroupID: groupID}
}

// AuthSession loads edgerc config and set up the client
func AuthSession() session.Session {

	edgerc := edgegrid.Must(edgegrid.New(edgegrid.WithFile(".edgerc"), edgegrid.WithSection("default")))

	session, err := session.New(session.WithLog(log.Log), session.WithSigner(edgerc))
	if err != nil {
		log.Fatalf("session was not configured: %[1]v", err)
	}
	return session
}

// GetPAPIClient returns a client to work with PAPI APIs
func GetPAPIClient(s session.Session) papi.PAPI {
	return papi.Client(s, papi.WithUsePrefixes(true))
}

// GetAppSecClient returns a client to work with AppSec APIs
func GetAppSecClient(s session.Session) appsec.APPSEC {
	return appsec.Client(s)
}

// GetNetListClient returns a client to work with Network List APIs
func GetNetListClient(s session.Session) netlist.NETLIST {
	return netlist.Client(s)
}

func getContractsGeneric(s session.Session) string {
	req, err := http.NewRequest("GET", "/papi/v1/contracts", nil)
	if err != nil {
		log.Fatalf("request was not set up: %[1]v", err)
	}

	var out *papi.GetContractsResponse
	_, err = s.Exec(req, &out)
	if err != nil {
		log.Fatalf("session was not signed or executed, %[1]v", err)
	}

	contracts := out.Contracts.Items
	for _, c := range contracts {
		log.Infof("Contract ID: %[1]s, Contract Type: %[2]s", c.ContractID, c.ContractTypeName)
	}
	contractID := contracts[0].ContractID

	return contractID
}

func listSecConfigsGeneric(s session.Session) {
	req, err := http.NewRequest("GET", "/appsec/v1/configs", nil)
	if err != nil {
		log.Fatalf("request was not set up: %[1]v", err)
	}

	resp, err := s.Exec(req, nil)
	if err != nil {
		log.Fatalf("session was not signed or executed, %[1]v", err)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("err: %v", err)
	}
	bodyString := string(bodyBytes)
	log.Info(bodyString)
}

func listGroupsGeneric(s session.Session) {
	req, err := http.NewRequest("GET", "/papi/v1/groups", nil)
	if err != nil {
		log.Fatalf("request was not set up: %[1]v", err)
	}

	var out *papi.GetGroupsResponse
	_, err = s.Exec(req, &out)
	if err != nil {
		log.Fatalf("session was not signed or executed, %[1]v", err)
	}
	groups := out.Groups.Items

	for _, g := range groups {
		log.Infof("Group ID: %[1]s, Group Name: %[2]s", g.GroupID, g.GroupName)
	}
}

func listSecConfigs(ctx context.Context, client appsec.APPSEC) {

	out, err := client.GetConfigs(ctx)
	if err != nil {
		log.Fatalf("session was not signed or executed, %[1]v", err)
	}

	configs := out.ConfigItems.Configs

	for _, c := range configs {
		log.Infof("Config ID: %[1]s, Config Name: %[2]s", c.ID, c.Name)
	}
}

func listSecConfigVersion(ctx context.Context, client appsec.APPSEC, configID int) {

	out, err := client.GetConfigVersions(ctx, configID, "-1", "50", "true")
	if err != nil {
		log.Fatalf("session was not signed or executed, %[1]v", err)
	}

	versions := out.VersionList
	log.Infof("Version: %[1]d, Version Notes: %[2]s", versions[len(versions)-1].Version, versions[len(versions)-1].VersionNotes)
}

func listGroups(ctx context.Context, client papi.PAPI, contractID string) {

	out, err := client.GetGroups(ctx)
	if err != nil {
		log.Fatalf("session was not signed or executed, %[1]v", err)
	}

	groups := out.Groups.Items
	for _, g := range groups {
		log.Infof("Group ID: %[1]s, Group Name: %[2]s", g.GroupID, g.GroupName)
	}
}

func listProducts(ctx context.Context, client papi.PAPI, contractID string) {

	params := papi.GetProductsRequest{ContractID: contractID}
	out, err := client.GetProducts(ctx, params)
	if err != nil {
		log.Fatalf("session was not signed or executed, %[1]v", err)
	}
	log.Infof("%v", out)
}

func listPolicies(ctx context.Context, client appsec.APPSEC, configID, versionNumber int) {

	out, err := client.GetPolicies(ctx, configID, versionNumber)
	if err != nil {
		log.Fatalf("session was not signed or executed, %[1]v", err)
	}

	policies := out.Policies
	for _, p := range policies {
		log.Infof("Policy ID: %[1]d, Policy Name: %[2]s", p.PolicyID, p.PolicyName)
	}
}

func listRules(ctx context.Context, client appsec.APPSEC, configID, versionNumber int, policyID string) {

	out, err := client.GetRules(ctx, configID, 1, policyID)
	if err != nil {
		log.Fatalf("session was not signed or executed, %[1]v", err)
	}

	actions := out.RuleActions
	for _, a := range actions {
		log.Infof("Action ID: %[1]d, Action Type: %[2]s", a.ID, a.Action)
	}
}

func listNetworkLists(ctx context.Context, client netlist.NETLIST) {

	params := netlist.ListNetworkListsRequest{
		OptionalParams: &netlist.OptionalParams{
			Extended:        true,
			IncludeElements: true,
		},
		ListType: netlist.IP,
	}

	out, err := client.ListNetworkLists(ctx, params)
	if err != nil {
		log.Fatalf("session was not signed or executed, %[1]v", err)
	}

	lists := out.NetworkLists
	for _, l := range lists {
		log.Infof("Unique ID: %[1]s, Is activated on Staging: %[2]s", l.UniqueID, l.Links.ActivateInStaging)
	}
}

func getNetworkList(ctx context.Context, client netlist.NETLIST, networkListID string) {

	params := netlist.GetNetworkListRequest{
		OptionalParams: &netlist.OptionalParams{
			Extended:        true,
			IncludeElements: true,
		},
		NetworkListID: networkListID,
	}

	out, err := client.GetNetworkList(ctx, params)
	if err != nil {
		log.Fatalf("session was not signed or executed, %[1]v", err)
	}

	listType := out.Type
	var logType string
	if listType == "GEO" {
		logType = "Country"
	} else {
		logType = "IP address"
	}
	listIP := out.List
	for _, ip := range listIP {
		log.Infof("%[1]s: %[2]s", logType, ip)
	}
}

func createNetworkList(ctx context.Context, client netlist.NETLIST, NLType netlist.NetworkType, NList []string, contractDetails interface{}) string {

	params := netlist.CreateNetworkListRequest{
		BodyNetworkListRequest: &netlist.BodyNetworkListRequest{
			Name:        "My list created via Network List API",
			Type:        NLType.String(),
			Description: "The list is maintained by a Golang library",
			List:        NList,
		},
	}

	if contractDetails != nil {
		switch c := contractDetails.(type) {
		case ContractParams:
			params.ContractID = c.ContractID
			params.GroupID = c.GroupID
		default:
			log.Fatalf("incorrect parameters type: %v", c)
		}
	}

	out, err := client.CreateNetworkList(ctx, params)
	if err != nil {
		log.Fatalf("session was not signed or executed, %[1]v", err)
	}

	log.Infof("Unique ID os the created list: %[1]s, SyncPoint: %[2]d", out.UniqueID, out.SyncPoint)
	return out.UniqueID
}

func updateNetworkList(ctx context.Context, client netlist.NETLIST, listID string) {

	params := netlist.UpdateNetworkListRequest{
		BodyNetworkListRequest: &netlist.BodyNetworkListRequest{
			GetNetworkListRequest: &netlist.GetNetworkListRequest{
				OptionalParams: &netlist.OptionalParams{
					Extended:        true,
					IncludeElements: true,
				},
				NetworkListID: listID,
			},
			Name:        "Include one country",
			Type:        netlist.GEO.String(),
			Description: "Updated notes",
			List:        []string{"CH"},
		},
	}

	out, err := client.UpdateNetworkList(ctx, params)
	if err != nil {
		log.Fatalf("session was not signed or executed, %[1]v", err)
	}

	countries := out.List
	for _, c := range countries {
		log.Infof("Country: %s", c)
	}
}

func deleteNetworkList(ctx context.Context, client netlist.NETLIST, listID string) {

	params := netlist.GetNetworkListRequest{
		NetworkListID: listID,
	}

	out, err := client.DeleteNetworkList(ctx, params)
	if err != nil {
		log.Fatalf("session was not signed or executed, %[1]v", err)
	}

	log.Infof("Delete Status: %d", out.Status)
}

func main() {
	log.SetHandler(text.New(os.Stdout))
	ctx := context.Background()
	session := AuthSession()
	// papiClient := GetPapiClient(session)
	// appsecClient := GetAppSecClient(session)
	netlistClient := GetNetListClient(session)

	// IPList := randomIP()
	countries := ISOCountries()

	// listNetworkLists(ctx, netlistClient)
	// listIP := createNetworkList(ctx, netlistClient, netlist.IP, IPList)
	contractID := getContractsGeneric(session)
	acg := 179988 // this is my ACG which I retrieved via listGroups
	params := NewContractParams(strings.TrimPrefix(contractID, "ctr_"), acg)
	listGEO := createNetworkList(ctx, netlistClient, netlist.GEO, countries, params)
	getNetworkList(ctx, netlistClient, listGEO)
	updateNetworkList(ctx, netlistClient, listGEO)
	deleteNetworkList(ctx, netlistClient, listGEO)
	// listProducts(ctx, papiClient, contractID)
	// listSecConfigsGeneric(session)
	// listGroups(ctx, papiClient, contractID)
	// listSecConfigs(ctx, appsecClient)
	// listSecConfigVersion(ctx, appsecClient, 69058)
	// listPolicies(ctx, appsecClient, 69058, 50)
	// listRules(ctx, appsecClient, 69058, 50, "1234_112176")
}
