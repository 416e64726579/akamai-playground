package main

import (
	"context"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/akamai-playground/appsec"
	"github.com/akamai-playground/netlist"

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
func AuthSession() (session.Session, error) {

	edgerc := edgegrid.Must(edgegrid.New(edgegrid.WithFile(".edgerc"), edgegrid.WithSection("default")))

	session, err := session.New(session.WithLog(log.Log), session.WithSigner(edgerc))
	if err != nil {
		return nil, err
	}
	return session, nil
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

func getContractsGeneric(s session.Session) (string, error) {
	req, err := http.NewRequest("GET", "/papi/v1/contracts", nil)
	if err != nil {
		return "", err
	}

	var out *papi.GetContractsResponse
	_, err = s.Exec(req, &out)
	if err != nil {
		return "", err
	}

	contracts := out.Contracts.Items
	for _, c := range contracts {
		log.Infof("Contract ID: %[1]s, Contract Type: %[2]s", c.ContractID, c.ContractTypeName)
	}
	contractID := contracts[0].ContractID

	return contractID, nil
}

func listSecConfigsGeneric(s session.Session) error {
	req, err := http.NewRequest("GET", "/appsec/v1/configs", nil)
	if err != nil {
		return err
	}

	resp, err := s.Exec(req, nil)
	if err != nil {
		return err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	bodyString := string(bodyBytes)
	log.Info(bodyString)
	return nil
}

func listGroupsGeneric(s session.Session) error {
	req, err := http.NewRequest("GET", "/papi/v1/groups", nil)
	if err != nil {
		log.Fatalf("request was not set up: %[1]v", err)
	}

	var out *papi.GetGroupsResponse
	_, err = s.Exec(req, &out)
	if err != nil {
		return err
	}
	groups := out.Groups.Items

	for _, g := range groups {
		log.Infof("Group ID: %[1]s, Group Name: %[2]s", g.GroupID, g.GroupName)
	}
	return nil
}

func listSecConfigs(ctx context.Context, client appsec.APPSEC) error {

	out, err := client.GetConfigs(ctx)
	if err != nil {
		return err
	}

	configs := out.ConfigItems.Configs

	for _, c := range configs {
		log.Infof("Config ID: %[1]s, Config Name: %[2]s", c.ID, c.Name)
	}
	return nil
}

func listSecConfigVersion(ctx context.Context, client appsec.APPSEC, configID int) error {

	out, err := client.GetConfigVersions(ctx, configID, "-1", "50", "true")
	if err != nil {
		return err
	}

	versions := out.VersionList
	log.Infof("Version: %[1]d, Version Notes: %[2]s", versions[len(versions)-1].Version, versions[len(versions)-1].VersionNotes)
	return nil
}

func listGroups(ctx context.Context, client papi.PAPI, contractID string) error {

	out, err := client.GetGroups(ctx)
	if err != nil {
		return err
	}

	groups := out.Groups.Items
	for _, g := range groups {
		log.Infof("Group ID: %[1]s, Group Name: %[2]s", g.GroupID, g.GroupName)
	}
	return nil
}

func listProducts(ctx context.Context, client papi.PAPI, contractID string) error {

	params := papi.GetProductsRequest{ContractID: contractID}
	out, err := client.GetProducts(ctx, params)
	if err != nil {
		return err
	}
	log.Infof("%v", out)
	return nil
}

func listPolicies(ctx context.Context, client appsec.APPSEC, configID, versionNumber int) error {

	out, err := client.GetPolicies(ctx, configID, versionNumber)
	if err != nil {
		return err
	}

	policies := out.Policies
	for _, p := range policies {
		log.Infof("Policy ID: %[1]d, Policy Name: %[2]s", p.PolicyID, p.PolicyName)
	}
	return nil
}

func listRules(ctx context.Context, client appsec.APPSEC, configID, versionNumber int, policyID string) error {

	out, err := client.GetRules(ctx, configID, 1, policyID)
	if err != nil {
		return err
	}

	actions := out.RuleActions
	for _, a := range actions {
		log.Infof("Action ID: %[1]d, Action Type: %[2]s", a.ID, a.Action)
	}
	return nil
}

func listNetworkLists(ctx context.Context, client netlist.NETLIST) error {

	params := netlist.ListNetworkListsRequest{
		OptionalParams: &netlist.OptionalParams{
			Extended:        true,
			IncludeElements: true,
		},
		ListType: netlist.IP,
	}

	out, err := client.ListNetworkLists(ctx, params)
	if err != nil {
		return err
	}

	lists := out.NetworkLists
	for _, l := range lists {
		log.Infof("Unique ID: %[1]s, Link to activate on Staging: %[2]s", l.UniqueID, l.Links.ActivateInStaging)
	}
	return nil
}

func getNetworkList(ctx context.Context, client netlist.NETLIST, networkListID string) error {

	params := netlist.GetNetworkListRequest{
		OptionalParams: &netlist.OptionalParams{
			Extended:        true,
			IncludeElements: true,
		},
		NetworkListID: networkListID,
	}

	out, err := client.GetNetworkList(ctx, params)
	if err != nil {
		return err
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
	return nil
}

func createNetworkList(ctx context.Context, client netlist.NETLIST, NLType netlist.NetworkType, NList []string, contractDetails ...interface{}) (string, error) {

	params := netlist.CreateNetworkListRequest{
		BodyNetworkListRequest: &netlist.BodyNetworkListRequest{
			Name:        "My list created via Network List API",
			Type:        NLType.String(),
			Description: "The list is maintained by a Golang library",
			List:        NList,
		},
	}

	if contractDetails != nil && len(contractDetails) <= 1 {
		switch c := contractDetails[0].(type) {
		case ContractParams:
			params.ContractID = c.ContractID
			params.GroupID = c.GroupID
		default:
			log.Fatalf("incorrect parameters type: %v", c)
		}
	}

	out, err := client.CreateNetworkList(ctx, params)
	if err != nil {
		return "", err
	}

	log.Infof("Unique ID os the created list: %[1]s, SyncPoint: %[2]d", out.UniqueID, out.SyncPoint)
	return out.UniqueID, nil
}

func updateNetworkList(ctx context.Context, client netlist.NETLIST, listID string) error {

	params := netlist.UpdateNetworkListRequest{
		BodyNetworkListRequest: &netlist.BodyNetworkListRequest{
			GetNetworkListRequest: &netlist.GetNetworkListRequest{
				OptionalParams: &netlist.OptionalParams{
					Extended:        true,
					IncludeElements: true,
				},
				NetworkListID: listID,
			},
			Name:        "Updated List of Countries",
			Type:        netlist.GEO.String(),
			Description: "Updated Notes",
			List:        []string{"CH"},
		},
	}

	out, err := client.UpdateNetworkList(ctx, params)
	if err != nil {
		return err
	}

	countries := out.List
	for _, c := range countries {
		log.Infof("Country: %s", c)
	}
	return nil
}

func appendIPNetworkList(ctx context.Context, client netlist.NETLIST, listID string) error {

	params := netlist.AppendListRequest{
		NetworkListID: listID,
		List:          []string{"1.1.1.1"},
	}

	out, err := client.AppendList(ctx, params)
	if err != nil {
		return err
	}

	IPList := out.List
	for _, c := range IPList {
		log.Infof("IP address: %s", c)
	}
	return nil
}

func deleteNetworkList(ctx context.Context, client netlist.NETLIST, listID string) error {

	params := netlist.DeleteNetworkListRequest{
		GetNetworkListRequest: &netlist.GetNetworkListRequest{
			NetworkListID: listID,
		},
	}

	out, err := client.DeleteNetworkList(ctx, params)
	if err != nil {
		return err
	}

	log.Infof("Delete Status: %d", out.Status)
	return nil
}

func appendNetworkList(ctx context.Context, client netlist.NETLIST, listID string) error {

	params := netlist.AppendListRequest{
		NetworkListID: listID,
		List:          []string{"RU", "US"},
	}

	out, err := client.AppendList(ctx, params)
	if err != nil {
		return err
	}

	countries := out.List
	for _, c := range countries {
		log.Infof("Country: %s", c)
	}
	return nil
}

func addElement(ctx context.Context, client netlist.NETLIST, listID string) error {

	params := netlist.AddElementRequest{
		NetworkListID: listID,
		Element:       "GB",
	}

	out, err := client.AddElement(ctx, params)
	if err != nil {
		return err
	}

	countries := out.List
	for _, c := range countries {
		log.Infof("Country: %s", c)
	}
	return nil
}

func removeElement(ctx context.Context, client netlist.NETLIST, listID string) error {

	params := netlist.RemoveElementRequest{
		AddElementRequest: &netlist.AddElementRequest{
			NetworkListID: listID,
			Element:       "US",
		},
	}

	out, err := client.RemoveElement(ctx, params)
	if err != nil {
		return err
	}

	countries := out.List
	for _, c := range countries {
		log.Infof("Country: %s", c)
	}
	return nil
}

func activateNetworkList(ctx context.Context, client netlist.NETLIST, listID string) error {

	params := netlist.ActivateNetworkListRequest{
		NetworkListID:          listID,
		Environment:            netlist.STAGING,
		Comments:               "Update via code",
		NotificationRecipients: []string{"andrey.petriv1@gmail.com"},
	}

	out, err := client.ActivateNetworkList(ctx, params)
	if err != nil {
		return err
	}

	log.Infof("%d", out.ActivationID)
	return nil
}

func getActivationNetworkList(ctx context.Context, client netlist.NETLIST, listID string) error {

	params := netlist.ActivateNetworkListRequest{
		NetworkListID: listID,
		Environment:   netlist.STAGING,
	}

	out, err := client.GetActivationNetworkList(ctx, params)
	if err != nil {
		return err
	}

	log.Infof("%s", out.ActivationStatus)
	return nil
}

func getActivationSnapshot(ctx context.Context, client netlist.NETLIST, listID string) error {

	params := netlist.GetActivationSnapshotRequest{
		NetworkListID: listID,
		SyncPoint:     0,
		Extended:      true,
	}

	out, err := client.GetActivationSnapshot(ctx, params)
	if err != nil {
		return err
	}

	log.Infof("%s", out.Name)
	return nil
}

func updateNLDetails(ctx context.Context, client netlist.NETLIST, listID string) error {

	params := netlist.UpdateNetworkListDetailsRequest{
		NetworkListID: listID,
		Name:          "Update Network List Details Name",
		Description:   "Update Network List Details Description",
	}

	err := client.UpdateNetworkListDetails(ctx, params)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	log.SetHandler(text.New(os.Stdout))
	ctx := context.Background()
	session, err := AuthSession()
	if err != nil {
		log.Fatalf("session was not signed or executed with an error: %v", err)
	}
	// papiClient := GetPapiClient(session)
	// appsecClient := GetAppSecClient(session)
	netlistClient := GetNetListClient(session)

	// listProducts(ctx, papiClient, contractID)
	// listSecConfigsGeneric(session)
	// listGroups(ctx, papiClient, contractID)
	// listSecConfigs(ctx, appsecClient)
	// listSecConfigVersion(ctx, appsecClient, 69058)
	// listPolicies(ctx, appsecClient, 69058, 50)
	// listRules(ctx, appsecClient, 69058, 50, "1234_112176")

	// IPList := randomIP()
	// countries := ISOCountries()

	// listNetworkLists(ctx, netlistClient)
	// listIP := createNetworkList(ctx, netlistClient, netlist.IP, IPList)
	// contractID, err = getContractsGeneric(session)
	// if err != nil {
	// 	log.Fatalf("session was not signed or executed with an error: %v", err)
	// }

	// listNetworkLists(ctx, netlistClient)

	// acg := 179988 // this is my ACG which I retrieved via listGroups
	// params := NewContractParams(strings.TrimPrefix(contractID, "ctr_"), acg)
	// listGEO, err := createNetworkList(ctx, netlistClient, netlist.GEO, countries, params)
	// if err != nil {
	// 	log.Fatalf("session was not signed or executed with an error: %v", err)
	// }
	// defer deleteNetworkList(ctx, netlistClient, listGEO)
	// getNetworkList(ctx, netlistClient, listGEO)
	// updateNetworkList(ctx, netlistClient, listGEO)
	// if err := appendNetworkList(ctx, netlistClient, listGEO); err != nil {
	// 	log.Errorf("%v", err)
	// }

	// if err := addElement(ctx, netlistClient, listGEO); err != nil {
	// 	log.Errorf("%v", err)
	// }
	// if err := removeElement(ctx, netlistClient, listGEO); err != nil {
	// 	log.Errorf("%v", err)
	// }

	listID := ""
	if err := appendIPNetworkList(ctx, netlistClient, listID); err != nil {
		log.Errorf("%v", err)
	}
	if err := activateNetworkList(ctx, netlistClient, listID); err != nil {
		log.Errorf("%v", err)
	}
	if err := getActivationNetworkList(ctx, netlistClient, listID); err != nil {
		log.Errorf("%v", err)
	}

	if err := getActivationSnapshot(ctx, netlistClient, listID); err != nil {
		log.Errorf("%v", err)
	}

	if err := updateNLDetails(ctx, netlistClient, listID); err != nil {
		log.Errorf("%v", err)
	}

}
