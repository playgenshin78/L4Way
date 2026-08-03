package management

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlv1 "flux.local/flux/gen/control/v1"
	"flux.local/flux/internal/cluster"
	shared "flux.local/flux/internal/control"
	controllercontrol "flux.local/flux/internal/controller/control"
	"flux.local/flux/internal/controller/iam"
	"flux.local/flux/internal/controller/store"
	"flux.local/flux/internal/securechannel"
	"flux.local/flux/internal/spec"
)

type fakeNodeCommander struct {
	calls []struct {
		nodeID  string
		request controllercontrol.CommandRequest
	}
}

func (f *fakeNodeCommander) Dispatch(_ context.Context, nodeID string, request controllercontrol.CommandRequest) (*controlv1.NodeCommandResult, error) {
	f.calls = append(f.calls, struct {
		nodeID  string
		request controllercontrol.CommandRequest
	}{nodeID: nodeID, request: request})
	result := &controlv1.NodeCommandResult{
		RequestId:       "management-test-command",
		Kind:            request.Kind,
		Success:         true,
		CompletedAtUnix: time.Now().UTC().Unix(),
	}
	if request.Kind == controlv1.NodeCommandKind_NODE_COMMAND_KIND_TCP_CHECK {
		result.LatencyMicros = 12_400
	}
	return result, nil
}

func TestManagementOwnerTenantAuthorizationAndCSRF(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := store.Open(ctx, filepath.Join(t.TempDir(), "flux.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	ownerHash, err := iam.HashPassword("owner-password-for-management-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateOwner(ctx, "owner", "Owner", ownerHash); err != nil {
		t.Fatal(err)
	}
	for _, nodeID := range []string{"node-a", "node-b"} {
		if _, _, err := repository.CreateEnrollmentToken(ctx, nodeID, 10*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	capabilities, _ := json.Marshal(shared.DefaultCapabilities())
	if err := repository.RecordHello(ctx, store.HelloRecord{NodeID: "node-a", AgentVersion: "test", Capabilities: capabilities, ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	initialPlan := cluster.Plan{
		SchemaVersion: cluster.PlanSchemaVersionV1, ID: "default", Revision: 1, NodeOfflineAfterSeconds: 90,
		Nodes: []cluster.Node{{
			ID: "node-a", Enabled: true, Roles: []cluster.NodeRole{cluster.RoleIngress},
			ListenIPs:     []netip.Addr{netip.MustParseAddr("198.51.100.10")},
			FailureDomain: "zone-a", Capacity: cluster.Capacity{MaxForwards: 100},
		}},
	}
	if _, err := repository.ApplyClusterPlan(ctx, initialPlan, "owner:test"); err != nil {
		t.Fatal(err)
	}
	settleManagementRollout(t, repository, "default", "node-a")
	controllerIdentity, err := securechannel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	commands := &fakeNodeCommander{}
	server, err := New(repository, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{
		SessionTTL: time.Hour, CookieSecure: false, ControllerPublicKey: securechannel.EncodePublicKey(controllerIdentity.Public),
		PublicEnrollmentAddress: "controller.example:8443", PublicControlAddress: "controller.example:9443",
		NodeInstallerURL: "https://downloads.example/flux/install.sh", NodeReleaseURL: "https://downloads.example/flux/flux-test.tar.gz",
		NodeCommands: commands,
	})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	ownerClient := testHTTPClient(t)
	loginResponse := requestJSON(t, ownerClient, http.MethodPost, httpServer.URL+"/api/v1/auth/login", `{"username":"owner","password":"owner-password-for-management-test"}`, "")
	if loginResponse.status != http.StatusOK {
		t.Fatalf("Owner login status=%d body=%s", loginResponse.status, loginResponse.body)
	}
	ownerCSRF := cookieValue(t, ownerClient, httpServer.URL, csrfCookieName)
	if ownerCSRF == "" {
		t.Fatal("Owner CSRF cookie is empty")
	}
	installCommand := requestJSON(t, ownerClient, http.MethodPost, httpServer.URL+"/api/v1/nodes/install-command", `{"node_id":"node-c","ttl_seconds":300}`, ownerCSRF)
	if installCommand.status != http.StatusCreated || !bytes.Contains(installCommand.body, []byte(`curl --fail`)) ||
		!bytes.Contains(installCommand.body, []byte(`bash -s -- agent --release-url`)) ||
		!bytes.Contains(installCommand.body, []byte(`--enable-fabric`)) || !bytes.Contains(installCommand.body, []byte(`"node_id":"node-c"`)) {
		t.Fatalf("node install command status=%d body=%s", installCommand.status, installCommand.body)
	}
	ownerNodes := requestJSON(t, ownerClient, http.MethodGet, httpServer.URL+"/api/v1/nodes", "", "")
	if ownerNodes.status != http.StatusOK || !bytes.Contains(ownerNodes.body, []byte(`"id":"node-c"`)) {
		t.Fatalf("Owner node list status=%d body=%s", ownerNodes.status, ownerNodes.body)
	}
	protocolPolicy := requestJSON(t, ownerClient, http.MethodPatch, httpServer.URL+"/api/v1/nodes/node-a/protocol-blocks",
		`{"resource_version":1,"protocol_blocks":{"http":true,"https":true,"socks":true,"tls":true}}`, ownerCSRF)
	if protocolPolicy.status != http.StatusNoContent {
		t.Fatalf("update node protocol policy status=%d body=%s", protocolPolicy.status, protocolPolicy.body)
	}
	settleManagementRollout(t, repository, "default", "node-a")
	policyPlan, err := repository.ActiveClusterPlan(ctx, "default")
	if err != nil || policyPlan.Plan.Nodes[0].ProtocolBlocks == nil || !policyPlan.Plan.Nodes[0].ProtocolBlocks.HTTP || !policyPlan.Plan.Nodes[0].ProtocolBlocks.HTTPS || !policyPlan.Plan.Nodes[0].ProtocolBlocks.SOCKS || !policyPlan.Plan.Nodes[0].ProtocolBlocks.TLS {
		t.Fatalf("node protocol policy was not persisted: %+v err=%v", policyPlan.Plan.Nodes[0].ProtocolBlocks, err)
	}
	policySnapshot, exists, err := repository.LatestSnapshot(ctx, "node-a")
	if err != nil || !exists || !bytes.Contains(policySnapshot.DesiredStateJSON, []byte(`"protocol_blocks":{"http":true,"https":true,"socks":true,"tls":true}`)) || !bytes.Contains(policySnapshot.RequiredCapabilities, []byte(`"nft.protocol-block"`)) {
		t.Fatalf("node protocol policy snapshot is incomplete: exists=%v err=%v desired=%s capabilities=%s", exists, err, policySnapshot.DesiredStateJSON, policySnapshot.RequiredCapabilities)
	}
	ownerNodes = requestJSON(t, ownerClient, http.MethodGet, httpServer.URL+"/api/v1/nodes", "", "")
	if ownerNodes.status != http.StatusOK || !bytes.Contains(ownerNodes.body, []byte(`"protocol_blocks":{"http":true,"https":true,"socks":true,"tls":true}`)) {
		t.Fatalf("Owner node policy view status=%d body=%s", ownerNodes.status, ownerNodes.body)
	}
	revokedNode := requestJSON(t, ownerClient, http.MethodPost, httpServer.URL+"/api/v1/nodes/node-c/revoke", `{}`, ownerCSRF)
	if revokedNode.status != http.StatusNoContent {
		t.Fatalf("revoke node status=%d body=%s", revokedNode.status, revokedNode.body)
	}
	reissueRevoked := requestJSON(t, ownerClient, http.MethodPost, httpServer.URL+"/api/v1/nodes/install-command", `{"node_id":"node-c","ttl_seconds":300}`, ownerCSRF)
	if reissueRevoked.status != http.StatusConflict {
		t.Fatalf("reissue revoked node status=%d body=%s", reissueRevoked.status, reissueRevoked.body)
	}
	pendingInstall := requestJSON(t, ownerClient, http.MethodPost, httpServer.URL+"/api/v1/nodes/install-command", `{"node_id":"node-d","ttl_seconds":300}`, ownerCSRF)
	if pendingInstall.status != http.StatusCreated {
		t.Fatalf("create pending node status=%d body=%s", pendingInstall.status, pendingInstall.body)
	}
	deletePending := requestJSON(t, ownerClient, http.MethodDelete, httpServer.URL+"/api/v1/nodes/node-d", "", ownerCSRF)
	if deletePending.status != http.StatusNoContent {
		t.Fatalf("delete pending node status=%d body=%s", deletePending.status, deletePending.body)
	}
	deleteEnrolled := requestJSON(t, ownerClient, http.MethodDelete, httpServer.URL+"/api/v1/nodes/node-a", "", ownerCSRF)
	if deleteEnrolled.status != http.StatusConflict {
		t.Fatalf("delete enrolled node status=%d body=%s", deleteEnrolled.status, deleteEnrolled.body)
	}

	missingCSRF := requestJSON(t, ownerClient, http.MethodPost, httpServer.URL+"/api/v1/tenants", `{"id":"tenant-missing","name":"Missing","username":"missing","display_name":"Missing","password":"missing-password-value"}`, "")
	if missingCSRF.status != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d body=%s", missingCSRF.status, missingCSRF.body)
	}
	inlineTenant := requestJSON(t, ownerClient, http.MethodPost, httpServer.URL+"/api/v1/tenants", `{
      "id":"tenant-inline","name":"Inline","username":"tenant-inline","display_name":"Inline",
      "password":"inline-password-for-management-test",
      "policy":{
        "allowed_ingress_nodes":["node-a"],"allowed_exit_nodes":[],"allowed_listen_ips":["198.51.100.30"],
        "allowed_port_ranges":[{"start":30000,"end":30100}],"allowed_protocols":["tcp"],
        "allow_via_exit":false,"max_forwards":2,"ingress_rate_limit_bps":0,"egress_rate_limit_bps":0,
        "traffic_quota_bytes":0,"allowed_target_cidrs":["192.0.2.0/24"],"denied_target_cidrs":[]
      }
    }`, ownerCSRF)
	if inlineTenant.status != http.StatusCreated || !bytes.Contains(inlineTenant.body, []byte(`"max_forwards":2`)) {
		t.Fatalf("inline tenant policy status=%d body=%s", inlineTenant.status, inlineTenant.body)
	}

	created := requestJSON(t, ownerClient, http.MethodPost, httpServer.URL+"/api/v1/tenants", `{"id":"tenant-a","name":"Tenant A","username":"tenant-a","display_name":"Tenant A","password":"tenant-password-for-management-test"}`, ownerCSRF)
	if created.status != http.StatusCreated {
		t.Fatalf("create tenant status=%d body=%s", created.status, created.body)
	}

	policyBody := `{
      "allowed_ingress_nodes":["node-a"],"allowed_exit_nodes":["node-b"],
      "allowed_listen_ips":["198.51.100.10"],"allowed_port_ranges":[{"start":10000,"end":20000}],
      "allowed_protocols":["tcp","udp"],"allow_via_exit":true,"max_forwards":5,
      "ingress_rate_limit_bps":10000000,"egress_rate_limit_bps":20000000,"traffic_quota_bytes":1000000000,
      "allowed_target_cidrs":["10.0.0.0/8"],"denied_target_cidrs":["10.1.0.0/16"],"resource_version":1
    }`
	updated := requestJSON(t, ownerClient, http.MethodPatch, httpServer.URL+"/api/v1/tenants/tenant-a/policy", policyBody, ownerCSRF)
	if updated.status != http.StatusOK {
		t.Fatalf("update policy status=%d body=%s", updated.status, updated.body)
	}

	tenantClient := testHTTPClient(t)
	tenantLogin := requestJSON(t, tenantClient, http.MethodPost, httpServer.URL+"/api/v1/auth/login", `{"username":"tenant-a","password":"tenant-password-for-management-test"}`, "")
	if tenantLogin.status != http.StatusOK {
		t.Fatalf("Tenant login status=%d body=%s", tenantLogin.status, tenantLogin.body)
	}
	tenantCSRF := cookieValue(t, tenantClient, httpServer.URL, csrfCookieName)
	tenantNodePolicy := requestJSON(t, tenantClient, http.MethodPatch, httpServer.URL+"/api/v1/nodes/node-a/protocol-blocks",
		`{"resource_version":2,"protocol_blocks":{"http":false,"https":false,"socks":false,"tls":false}}`, tenantCSRF)
	if tenantNodePolicy.status != http.StatusForbidden {
		t.Fatalf("tenant changed node protocol policy status=%d body=%s", tenantNodePolicy.status, tenantNodePolicy.body)
	}
	tenantNodes := requestJSON(t, tenantClient, http.MethodGet, httpServer.URL+"/api/v1/nodes", "", "")
	if tenantNodes.status != http.StatusOK || !bytes.Contains(tenantNodes.body, []byte(`"id":"node-a"`)) || bytes.Contains(tenantNodes.body, []byte(`"id":"node-c"`)) || bytes.Contains(tenantNodes.body, []byte(`"protocol_blocks"`)) {
		t.Fatalf("Tenant node list status=%d body=%s", tenantNodes.status, tenantNodes.body)
	}

	listTenants := requestJSON(t, tenantClient, http.MethodGet, httpServer.URL+"/api/v1/tenants", "", "")
	if listTenants.status != http.StatusForbidden {
		t.Fatalf("Tenant list status=%d body=%s", listTenants.status, listTenants.body)
	}
	getOwnPolicy := requestJSON(t, tenantClient, http.MethodGet, httpServer.URL+"/api/v1/tenants/tenant-a/policy", "", "")
	if getOwnPolicy.status != http.StatusOK {
		t.Fatalf("Tenant own policy status=%d body=%s", getOwnPolicy.status, getOwnPolicy.body)
	}
	tenantPatch := requestJSON(t, tenantClient, http.MethodPatch, httpServer.URL+"/api/v1/tenants/tenant-a/policy", policyBody, tenantCSRF)
	if tenantPatch.status != http.StatusForbidden {
		t.Fatalf("Tenant policy update status=%d body=%s", tenantPatch.status, tenantPatch.body)
	}
	otherPolicy := requestJSON(t, tenantClient, http.MethodGet, httpServer.URL+"/api/v1/tenants/other/policy", "", "")
	if otherPolicy.status != http.StatusForbidden {
		t.Fatalf("other tenant policy status=%d body=%s", otherPolicy.status, otherPolicy.body)
	}

	validForward := `{
      "protocols":["tcp"],
      "listen":{"address":"198.51.100.10","port":12000},
      "target":{"address":"10.2.0.5","port":443},
      "path_mode":"direct","ingress_node_id":"node-a","enabled":true
    }`
	createdForward := requestJSON(t, tenantClient, http.MethodPost, httpServer.URL+"/api/v1/forwards", validForward, tenantCSRF)
	if createdForward.status != http.StatusCreated || !bytes.Contains(createdForward.body, []byte(`"tenant_id":"tenant-a"`)) {
		t.Fatalf("create forward status=%d body=%s", createdForward.status, createdForward.body)
	}
	var createdEnvelope struct {
		Data struct {
			Forward struct {
				ID              string `json:"id"`
				ResourceVersion uint64 `json:"resource_version"`
			} `json:"forward"`
		} `json:"data"`
	}
	if err := json.Unmarshal(createdForward.body, &createdEnvelope); err != nil || createdEnvelope.Data.Forward.ID == "" || createdEnvelope.Data.Forward.ResourceVersion != 1 {
		t.Fatalf("decode created forward: %v body=%s", err, createdForward.body)
	}
	forwardID := createdEnvelope.Data.Forward.ID
	tcpCheck := requestJSON(t, tenantClient, http.MethodPost, httpServer.URL+"/api/v1/forwards/"+forwardID+"/tcp-check", "", tenantCSRF)
	if tcpCheck.status != http.StatusOK || !bytes.Contains(tcpCheck.body, []byte(`"reachable":true`)) || !bytes.Contains(tcpCheck.body, []byte(`"latency_ms":12.4`)) {
		t.Fatalf("TCP check status=%d body=%s", tcpCheck.status, tcpCheck.body)
	}
	if len(commands.calls) != 1 || commands.calls[0].nodeID != "node-a" || commands.calls[0].request.Kind != controlv1.NodeCommandKind_NODE_COMMAND_KIND_TCP_CHECK {
		t.Fatalf("unexpected TCP check command: %+v", commands.calls)
	}
	upgrade := requestJSON(t, ownerClient, http.MethodPost, httpServer.URL+"/api/v1/nodes/node-a/upgrade", "", ownerCSRF)
	if upgrade.status != http.StatusAccepted || len(commands.calls) != 2 || commands.calls[1].request.Kind != controlv1.NodeCommandKind_NODE_COMMAND_KIND_AGENT_UPGRADE {
		t.Fatalf("upgrade status=%d body=%s calls=%+v", upgrade.status, upgrade.body, commands.calls)
	}
	managedPlan, err := repository.ActiveClusterPlan(ctx, "default")
	if err != nil || len(managedPlan.Plan.UserPolicies) != 1 ||
		managedPlan.Plan.UserPolicies[0].UserID != "tenant-a" ||
		managedPlan.Plan.UserPolicies[0].RateLimit == nil ||
		managedPlan.Plan.UserPolicies[0].TrafficQuota == nil {
		t.Fatalf("tenant-wide limits were not synchronized into the cluster plan: %+v err=%v", managedPlan.Plan.UserPolicies, err)
	}

	deniedTarget := strings.Replace(validForward, `"10.2.0.5"`, `"10.1.2.3"`, 1)
	deniedForward := requestJSON(t, tenantClient, http.MethodPost, httpServer.URL+"/api/v1/forwards", deniedTarget, tenantCSRF)
	if deniedForward.status != http.StatusForbidden {
		t.Fatalf("denied target status=%d body=%s", deniedForward.status, deniedForward.body)
	}
	listedForwards := requestJSON(t, tenantClient, http.MethodGet, httpServer.URL+"/api/v1/forwards", "", "")
	if listedForwards.status != http.StatusOK || !bytes.Contains(listedForwards.body, []byte(forwardID)) {
		t.Fatalf("list forwards status=%d body=%s", listedForwards.status, listedForwards.body)
	}
	settleManagementRollout(t, repository, "default", "node-a")

	updatedForwardBody := strings.TrimSuffix(validForward, "\n    }") + `,
      "resource_version":1
    }`
	updatedForwardBody = strings.Replace(updatedForwardBody, `"10.2.0.5"`, `"10.2.0.6"`, 1)
	updatedForward := requestJSON(t, tenantClient, http.MethodPatch, httpServer.URL+"/api/v1/forwards/"+forwardID, updatedForwardBody, tenantCSRF)
	if updatedForward.status != http.StatusOK || !bytes.Contains(updatedForward.body, []byte(`"resource_version":2`)) {
		t.Fatalf("update forward status=%d body=%s", updatedForward.status, updatedForward.body)
	}
	settleManagementRollout(t, repository, "default", "node-a")
	tightenedPolicy := strings.Replace(policyBody, `"denied_target_cidrs":["10.1.0.0/16"]`, `"denied_target_cidrs":["10.1.0.0/16","10.2.0.0/16"]`, 1)
	tightenedPolicy = strings.Replace(tightenedPolicy, `"resource_version":1`, `"resource_version":2`, 1)
	tightened := requestJSON(t, ownerClient, http.MethodPatch, httpServer.URL+"/api/v1/tenants/tenant-a/policy", tightenedPolicy, ownerCSRF)
	if tightened.status != http.StatusOK {
		t.Fatalf("tighten policy status=%d body=%s", tightened.status, tightened.body)
	}
	paused, err := repository.EnforceTenantForwardPolicies(ctx, "system:test", 10, time.Now().UTC())
	if err != nil || paused != 1 {
		t.Fatalf("enforce tightened policy paused=%d err=%v", paused, err)
	}
	settleManagementRollout(t, repository, "default", "node-a")
	pausedPlan, err := repository.ActiveClusterPlan(ctx, "default")
	if err != nil || len(pausedPlan.Plan.Forwards) != 1 || pausedPlan.Plan.Forwards[0].Lifecycle != spec.LifecyclePaused || pausedPlan.Plan.Forwards[0].ResourceVersion != 3 {
		t.Fatalf("policy enforcement did not pause forward: %+v err=%v", pausedPlan.Plan.Forwards, err)
	}

	deleting := requestJSON(t, tenantClient, http.MethodDelete, httpServer.URL+"/api/v1/forwards/"+forwardID+"?mode=force&resource_version=3", "", tenantCSRF)
	if deleting.status != http.StatusAccepted || !bytes.Contains(deleting.body, []byte(`"lifecycle":"force_deleting"`)) {
		t.Fatalf("delete forward status=%d body=%s", deleting.status, deleting.body)
	}
	settleManagementRollout(t, repository, "default", "node-a")
	finalized, err := repository.FinalizeClusterDeletes(ctx, "system:test", 10, time.Now().UTC())
	if err != nil || finalized != 1 {
		t.Fatalf("finalize forward deletion count=%d err=%v", finalized, err)
	}
	settleManagementRollout(t, repository, "default", "node-a")
	activePlan, err := repository.ActiveClusterPlan(ctx, "default")
	if err != nil || len(activePlan.Plan.Forwards) != 0 {
		t.Fatalf("deleted forward remained in plan: %+v err=%v", activePlan.Plan.Forwards, err)
	}
	uninstallReady := make(chan testResponse, 1)
	go func() {
		uninstallReady <- requestJSON(t, ownerClient, http.MethodPost, httpServer.URL+"/api/v1/nodes/node-a/uninstall", "", ownerCSRF)
	}()
	removedFromPlan := false
	for attempt := 0; attempt < 100; attempt++ {
		retiringPlan, readErr := repository.ActiveClusterPlan(ctx, "default")
		if readErr != nil {
			t.Fatal(readErr)
		}
		if len(retiringPlan.Plan.Nodes) == 0 {
			removedFromPlan = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !removedFromPlan {
		t.Fatal("uninstall did not remove the node from the active plan")
	}
	settleManagementRollout(t, repository, "default", "node-a")
	var uninstall testResponse
	select {
	case uninstall = <-uninstallReady:
	case <-time.After(5 * time.Second):
		t.Fatal("uninstall did not finish after the cleanup ACK")
	}
	if uninstall.status != http.StatusAccepted || len(commands.calls) != 3 || commands.calls[2].request.Kind != controlv1.NodeCommandKind_NODE_COMMAND_KIND_AGENT_UNINSTALL {
		t.Fatalf("uninstall status=%d body=%s calls=%+v", uninstall.status, uninstall.body, commands.calls)
	}
	retiredSnapshot, exists, err := repository.LatestSnapshot(ctx, "node-a")
	if err != nil || !exists {
		t.Fatalf("retired snapshot exists=%v err=%v", exists, err)
	}
	retiredDesired, err := spec.DecodeDesiredJSON(retiredSnapshot.DesiredStateJSON)
	if err != nil || !retiredDesiredState(retiredDesired, "node-a") {
		t.Fatalf("retired desired state=%+v err=%v", retiredDesired, err)
	}
	nodesAfterUninstall, err := repository.ListNodes(ctx, 10, 0)
	var uninstalledNode *store.NodeSummary
	for index := range nodesAfterUninstall {
		if nodesAfterUninstall[index].ID == "node-a" {
			uninstalledNode = &nodesAfterUninstall[index]
			break
		}
	}
	if err != nil || uninstalledNode == nil || uninstalledNode.RevokedAt == nil {
		t.Fatalf("uninstalled node identity was not revoked: %+v err=%v", nodesAfterUninstall, err)
	}

	audit := requestJSON(t, ownerClient, http.MethodGet, httpServer.URL+"/api/v1/audit?page_size=100", "", "")
	if audit.status != http.StatusOK || !bytes.Contains(audit.body, []byte(`"tenant.policy.update"`)) || !bytes.Contains(audit.body, []byte(`"node.protocol_blocks.update"`)) || !bytes.Contains(audit.body, []byte(`"authorization.denied"`)) || !bytes.Contains(audit.body, []byte(`"forward.tcp_check"`)) || !bytes.Contains(audit.body, []byte(`"node.upgrade"`)) || !bytes.Contains(audit.body, []byte(`"node.uninstall"`)) {
		t.Fatalf("audit status=%d body=%s", audit.status, audit.body)
	}
	usageResponse := requestJSON(t, ownerClient, http.MethodGet, httpServer.URL+"/api/v1/usage?days=7", "", "")
	if usageResponse.status != http.StatusOK || !bytes.Contains(usageResponse.body, []byte(`"range_days":7`)) ||
		!bytes.Contains(usageResponse.body, []byte(`"measurement"`)) {
		t.Fatalf("usage status=%d body=%s", usageResponse.status, usageResponse.body)
	}
	systemStatus := requestJSON(t, ownerClient, http.MethodGet, httpServer.URL+"/api/v1/system/status", "", "")
	if systemStatus.status != http.StatusOK || !bytes.Contains(systemStatus.body, []byte(`"Noise IK / X25519 / AES-256-GCM / SHA-256"`)) {
		t.Fatalf("system status=%d body=%s", systemStatus.status, systemStatus.body)
	}
	unconfiguredBackup := requestJSON(t, ownerClient, http.MethodPost, httpServer.URL+"/api/v1/system/backup", `{}`, ownerCSRF)
	if unconfiguredBackup.status != http.StatusConflict {
		t.Fatalf("unconfigured backup status=%d body=%s", unconfiguredBackup.status, unconfiguredBackup.body)
	}
	partialTenantUpdate := requestJSON(t, ownerClient, http.MethodPatch, httpServer.URL+"/api/v1/tenants/tenant-a",
		`{"status":"disabled","resource_version":1}`, ownerCSRF)
	if partialTenantUpdate.status != http.StatusOK || !bytes.Contains(partialTenantUpdate.body, []byte(`"status":"disabled"`)) ||
		!bytes.Contains(partialTenantUpdate.body, []byte(`"username":"tenant-a"`)) {
		t.Fatalf("partial tenant update status=%d body=%s", partialTenantUpdate.status, partialTenantUpdate.body)
	}
	passwordChange := requestJSON(t, ownerClient, http.MethodPost, httpServer.URL+"/api/v1/auth/password",
		`{"current_password":"owner-password-for-management-test","new_password":"owner-replacement-password"}`, ownerCSRF)
	if passwordChange.status != http.StatusNoContent {
		t.Fatalf("password change status=%d body=%s", passwordChange.status, passwordChange.body)
	}
	relogin := requestJSON(t, testHTTPClient(t), http.MethodPost, httpServer.URL+"/api/v1/auth/login",
		`{"username":"owner","password":"owner-replacement-password"}`, "")
	if relogin.status != http.StatusOK {
		t.Fatalf("replacement password login status=%d body=%s", relogin.status, relogin.body)
	}
}

func TestValidHTTPSDownloadURL(t *testing.T) {
	tests := map[string]bool{
		"https://downloads.example/flux/install.sh":                    true,
		"https://downloads.example/releases/flux.tar.gz?token=opaque":  true,
		"http://downloads.example/flux/install.sh":                     false,
		"https://user:password@downloads.example/flux/install.sh":      false,
		"https://downloads.example/flux/install.sh#fragment":           false,
		"https://downloads.example/flux/install\\script.sh":            false,
		"https://downloads.example/flux/install.sh' --malicious-flag":  false,
		"https://downloads.example/flux/install.sh\nmalicious-command": false,
	}
	for value, expected := range tests {
		if actual := validHTTPSDownloadURL(value); actual != expected {
			t.Errorf("validHTTPSDownloadURL(%q)=%v, want %v", value, actual, expected)
		}
	}
}

func TestChecksumURLForReleasePreservesQuery(t *testing.T) {
	actual := checksumURLForRelease("https://downloads.example/flux/release.tar.gz?token=opaque")
	if actual != "https://downloads.example/flux/release.tar.gz.sha256?token=opaque" {
		t.Fatalf("checksum URL=%q", actual)
	}
}

func TestPlanWithoutNodeRemovesReciprocalFabricLinks(t *testing.T) {
	plan := cluster.Plan{Nodes: []cluster.Node{
		{ID: "node-a", FabricLinks: []cluster.FabricLink{{ID: "ab", PeerNodeID: "node-b"}}},
		{ID: "node-b", FabricLinks: []cluster.FabricLink{{ID: "ba", PeerNodeID: "node-a"}, {ID: "bc", PeerNodeID: "node-c"}}},
		{ID: "node-c", FabricLinks: []cluster.FabricLink{{ID: "cb", PeerNodeID: "node-b"}}},
	}}
	result, removed := planWithoutNode(plan, "node-a")
	if !removed || len(result.Nodes) != 2 || result.Nodes[0].ID != "node-b" || len(result.Nodes[0].FabricLinks) != 1 || result.Nodes[0].FabricLinks[0].PeerNodeID != "node-c" {
		t.Fatalf("unexpected detached plan: %+v", result.Nodes)
	}
	if len(plan.Nodes) != 3 || len(plan.Nodes[1].FabricLinks) != 2 {
		t.Fatal("planWithoutNode mutated its input")
	}
}

func settleManagementRollout(t *testing.T, repository *store.Store, planID, nodeID string) {
	t.Helper()
	for attempt := 0; attempt < 12; attempt++ {
		status, err := repository.ClusterStatus(context.Background(), planID)
		if err != nil {
			t.Fatal(err)
		}
		switch status.LatestRollout {
		case "", "completed", "rolled_back":
			return
		case "failed":
			t.Fatalf("cluster rollout failed: %+v", status)
		}
		snapshot, exists, err := repository.LatestSnapshot(context.Background(), nodeID)
		if err != nil || !exists {
			t.Fatalf("latest snapshot exists=%v err=%v", exists, err)
		}
		if err := repository.RecordApplyResult(context.Background(), store.ApplyRecord{
			NodeID: nodeID, Generation: snapshot.Generation, DesiredChecksum: snapshot.DesiredChecksum,
			ProgramChecksum: strings.Repeat("d", 64), Status: "applied",
			ErrorCode: controlv1.ApplyErrorCode_APPLY_ERROR_CODE_NONE.String(), ObservedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.AdvanceClusterRollouts(context.Background(), "test-worker", 10, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("cluster rollout did not settle")
}

type testResponse struct {
	status int
	body   []byte
}

func testHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func requestJSON(t *testing.T, client *http.Client, method, url, body, csrf string) testResponse {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = bytes.NewBufferString(body)
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		request.Header.Set(csrfHeaderName, csrf)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 0 && response.StatusCode != http.StatusNoContent {
		var value any
		if err := json.Unmarshal(encoded, &value); err != nil {
			t.Fatalf("response is not JSON: %s", encoded)
		}
	}
	return testResponse{status: response.StatusCode, body: encoded}
}

func cookieValue(t *testing.T, client *http.Client, rawURL, name string) string {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range client.Jar.Cookies(request.URL) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	t.Fatalf("cookie %s was not found", name)
	return ""
}

func TestSystemBackupDownload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	repository, err := store.Open(ctx, filepath.Join(t.TempDir(), "flux.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	ownerHash, err := iam.HashPassword("owner-password-for-backup-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateOwner(ctx, "owner", "Owner", ownerHash); err != nil {
		t.Fatal(err)
	}
	backupDirectory := t.TempDir()
	backupCalls := 0
	server, err := New(repository, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{
		SessionTTL: time.Hour, CookieSecure: false, BackupDirectory: backupDirectory,
		Backup: func(_ context.Context, path string) error {
			backupCalls++
			return os.WriteFile(path, []byte("controller-backup-test"), 0o600)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	client := testHTTPClient(t)
	login := requestJSON(t, client, http.MethodPost, httpServer.URL+"/api/v1/auth/login", `{"username":"owner","password":"owner-password-for-backup-test"}`, "")
	if login.status != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.status, login.body)
	}
	csrf := cookieValue(t, client, httpServer.URL, csrfCookieName)
	missing := requestJSON(t, client, http.MethodPost, httpServer.URL+"/api/v1/system/backup/download", "", csrf)
	if missing.status != http.StatusNotFound || !strings.Contains(string(missing.body), "backup_not_found") {
		t.Fatalf("missing backup download status=%d body=%s", missing.status, missing.body)
	}
	create := requestJSON(t, client, http.MethodPost, httpServer.URL+"/api/v1/system/backup", `{}`, csrf)
	if create.status != http.StatusCreated {
		t.Fatalf("create backup status=%d body=%s", create.status, create.body)
	}
	request, err := http.NewRequest(http.MethodPost, httpServer.URL+"/api/v1/system/backup/download", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(csrfHeaderName, csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "controller-backup-test" {
		t.Fatalf("download status=%d body=%q", response.StatusCode, body)
	}
	if backupCalls != 1 {
		t.Fatalf("backup function called %d times; download must reuse the latest backup", backupCalls)
	}
	if response.Header.Get("Content-Type") != "application/gzip" ||
		!strings.Contains(response.Header.Get("Content-Disposition"), ".tar.gz") ||
		response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("download headers=%v", response.Header)
	}
}

func TestSourceIPTrustsForwardingHeadersOnlyFromLoopbackProxy(t *testing.T) {
	loopback := httptest.NewRequest(http.MethodGet, "http://controller.test/", nil)
	loopback.RemoteAddr = "127.0.0.1:43210"
	loopback.Header.Set("X-Forwarded-For", "203.0.113.44, 127.0.0.1")
	if actual := sourceIP(loopback); actual != "203.0.113.44" {
		t.Fatalf("loopback proxy source IP = %q", actual)
	}

	untrusted := httptest.NewRequest(http.MethodGet, "http://controller.test/", nil)
	untrusted.RemoteAddr = "198.51.100.20:43210"
	untrusted.Header.Set("X-Forwarded-For", "203.0.113.44")
	if actual := sourceIP(untrusted); actual != "198.51.100.20" {
		t.Fatalf("untrusted forwarded source IP = %q", actual)
	}
}

func TestLoginLimiterBoundsDistinctSourceWindowsAndExpiresThem(t *testing.T) {
	var limiter loginLimiter
	now := time.Now().UTC()
	for index := 0; index < maxLoginIPWindows; index++ {
		if !limiter.allow(fmt.Sprintf("198.51.%d.%d", index/256, index%256), now) {
			t.Fatalf("source %d was rejected before the limiter reached its bound", index)
		}
	}
	if limiter.allow("203.0.113.250", now) {
		t.Fatal("new source was accepted after the distinct-source bound was reached")
	}
	if !limiter.allow("203.0.113.250", now.Add(loginWindowTTL+time.Second)) {
		t.Fatal("expired source windows were not released")
	}
}
