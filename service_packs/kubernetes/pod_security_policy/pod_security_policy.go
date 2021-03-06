package pod_security_policy

//go:generate go-bindata.exe -pkg $GOPACKAGE -o assets/assets.go assets/yaml

import (
	"log"
	"strings"

	"path/filepath"

	"github.com/cucumber/godog"

	"github.com/citihub/probr/internal/coreengine"
	"github.com/citihub/probr/internal/utils"
	"github.com/citihub/probr/service_packs/kubernetes"
)

type ProbeStruct struct{}

var Probe ProbeStruct

// PodSecurityPolicy is the section of the kubernetes package which provides the kubernetes interactions required to support
// pod security policy
var psp PodSecurityPolicy

// SetPodSecurityPolicy allows injection of a specific PodSecurityPolicy helper.
func SetPodSecurityPolicy(p PodSecurityPolicy) {
	psp = p
}

// General

func (s *scenarioState) creationWillWithAMessage(arg1, arg2 string) error {
	return godog.ErrPending
}

func (s *scenarioState) aKubernetesClusterIsDeployed() error {
	description, payload := kubernetes.ClusterIsDeployed()
	s.audit.AuditScenarioStep(description, payload, nil)
	return nil // ClusterIsDeployed will create a fatal error if kubeconfig doesn't validate
}

// PENDING IMPLEMENTATION
func (s *scenarioState) aKubernetesDeploymentIsAppliedToAnExistingKubernetesCluster() error {

	//TODO: not sure this step is adding value ... return "pass" for now ...
	description := "Pending Implementation"
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, nil)
	return nil
}

func (s *scenarioState) theOperationWillWithAnError(res, msg string) error {
	err := kubernetes.AssertResult(&s.podState, res, msg)

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) performAllowedCommand() error {
	err := s.runVerificationProbe(VerificationProbe{Cmd: Ls, ExpectedExitCode: 0}) //'0' exit code as we expect this to succeed

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

// common helper funcs
func (s *scenarioState) runControlProbe(cf func() (*bool, error), c string) error {

	yesNo, err := cf()

	if err != nil {
		err = utils.ReformatError("error determining Pod Security Policy: %v error: %v", c, err)
		return err
	}
	if yesNo == nil {
		err = utils.ReformatError("result of %v is nil despite no error being raised from the call", c)
		log.Print(err)
		return err
	}

	if !*yesNo {
		return utils.ReformatError("%v is NOT restricted (result: %t)", c, *yesNo)
	}

	return nil
}

func (s *scenarioState) runVerificationProbe(c VerificationProbe) error {

	//check for lack of creation error, i.e. pod was created successfully
	if s.podState.CreationError == nil {
		res, err := psp.ExecPSPProbeCmd(&s.podState.PodName, c.Cmd, s.probe)

		//analyse the results
		if err != nil {
			//this is an error from trying to execute the command as opposed to
			//the command itself returning an error
			err = utils.ReformatError("Likely a misconfiguration error. Error raised trying to execute verification command (%v) - %v", c.Cmd, err)
			log.Print(err)
			return err
		}
		if res == nil {
			err = utils.ReformatError("<nil> result received when trying to execute verification command (%v)", c.Cmd)
			log.Print(err)
			return err
		}
		if res.Err != nil && res.Internal {
			//we have an error which was raised before reaching the cluster (i.e. it's "internal")
			//this indicates that the command was not successfully executed
			err = utils.ReformatError("Likely an internal Probr error. Error raised trying to execute verification command (%v)", c.Cmd)
			log.Print(err)
			return err
		}

		//we've managed to execution against the cluster.  This may have failed due to pod security, but this
		//is still a 'successful' execution.  The exit code of the command needs to be verified against expected
		//check the result against expected:
		if res.Code == c.ExpectedExitCode {
			//then as expected, test passes
			return nil
		}
		//else it's a fail:
		return utils.ReformatError("exit code %d from verification command %q did not match expected %d",
			res.Code, c.Cmd, c.ExpectedExitCode)
	}

	//pod wasn't created so nothing to test
	//TODO: really, we don't want to 'pass' this.  Is there an alternative?
	return nil
}

// TEST STEPS:

// CIS-5.2.1
// privileged access
func (s *scenarioState) privilegedAccessRequestIsMarkedForTheKubernetesDeployment(privilegedAccessRequested string) error {
	var pa bool
	if privilegedAccessRequested == "True" {
		pa = true
	} else {
		pa = false
	}

	pd, err := psp.CreatePODSettingSecurityContext(&pa, nil, nil, s.probe)

	err = kubernetes.ProcessPodCreationResult(&s.podState, pd, kubernetes.PSPNoPrivilege, err)

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) someControlExistsToPreventPrivilegedAccessForKubernetesDeploymentsToAnActiveKubernetesCluster() error {
	err := s.runControlProbe(psp.PrivilegedAccessIsRestricted, "PrivilegedAccessIsRestricted")

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) iShouldNotBeAbleToPerformACommandThatRequiresPrivilegedAccess() error {
	err := s.runVerificationProbe(VerificationProbe{Cmd: Chroot, ExpectedExitCode: 1})

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

// CIS-5.2.2
// hostPID
func (s *scenarioState) hostPIDRequestIsMarkedForTheKubernetesDeployment(hostPIDRequested string) error {

	var hostPID bool
	if hostPIDRequested == "True" {
		hostPID = true
	} else {
		hostPID = false
	}

	pd, err := psp.CreatePODSettingAttributes(&hostPID, nil, nil, s.probe)

	err = kubernetes.ProcessPodCreationResult(&s.podState, pd, kubernetes.PSPHostNamespace, err)

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) someSystemExistsToPreventAKubernetesContainerFromRunningUsingTheHostPIDOnTheActiveKubernetesCluster() error {
	err := s.runControlProbe(psp.HostPIDIsRestricted, "HostPIDIsRestricted")

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) iShouldNotBeAbleToPerformACommandThatProvidesAccessToTheHostPIDNamespace() error {
	err := s.runVerificationProbe(VerificationProbe{Cmd: EnterHostPIDNS, ExpectedExitCode: 1})

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

//CIS-5.2.3
func (s *scenarioState) hostIPCRequestIsMarkedForTheKubernetesDeployment(hostIPCRequested string) error {

	var hostIPC bool
	if hostIPCRequested == "True" {
		hostIPC = true
	} else {
		hostIPC = false
	}

	pd, err := psp.CreatePODSettingAttributes(nil, &hostIPC, nil, s.probe)

	err = kubernetes.ProcessPodCreationResult(&s.podState, pd, kubernetes.PSPHostNamespace, err)

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err

}

func (s *scenarioState) someSystemExistsToPreventAKubernetesDeploymentFromRunningUsingTheHostIPCInAnExistingKubernetesCluster() error {
	err := s.runControlProbe(psp.HostIPCIsRestricted, "HostIPCIsRestricted")

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) iShouldNotBeAbleToPerformACommandThatProvidesAccessToTheHostIPCNamespace() error {
	err := s.runVerificationProbe(VerificationProbe{Cmd: EnterHostIPCNS, ExpectedExitCode: 1})

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

//CIS-5.2.4
func (s *scenarioState) hostNetworkRequestIsMarkedForTheKubernetesDeployment(hostNetworkRequested string) error {

	var hostNetwork bool
	if hostNetworkRequested == "True" {
		hostNetwork = true
	} else {
		hostNetwork = false
	}

	pd, err := psp.CreatePODSettingAttributes(nil, nil, &hostNetwork, s.probe)

	err = kubernetes.ProcessPodCreationResult(&s.podState, pd, kubernetes.PSPHostNetwork, err)

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) someSystemExistsToPreventAKubernetesDeploymentFromRunningUsingTheHostNetworkInAnExistingKubernetesCluster() error {
	err := s.runControlProbe(psp.HostNetworkIsRestricted, "HostNetworkIsRestricted")

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err

}
func (s *scenarioState) iShouldNotBeAbleToPerformACommandThatProvidesAccessToTheHostNetworkNamespace() error {
	err := s.runVerificationProbe(VerificationProbe{Cmd: EnterHostNetworkNS, ExpectedExitCode: 1})

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

//CIS-5.2.5
func (s *scenarioState) privilegedEscalationIsMarkedForTheKubernetesDeployment(privilegedEscalationRequested string) error {

	allowPrivilegeEscalation := "true"
	if strings.ToLower(privilegedEscalationRequested) != "true" {
		allowPrivilegeEscalation = "false"
	}
	description := "Attempt to create a pod with privilege escalation set to " + allowPrivilegeEscalation

	y, err := utils.ReadStaticFile(kubernetes.AssetsDir, "psp-azp-privileges.yaml")
	if err == nil {
		yaml := utils.ReplaceBytesValue(y, "{{ allowPrivilegeEscalation }}", allowPrivilegeEscalation)
		pd, err := psp.CreatePodFromYaml(yaml, s.probe)
		err = kubernetes.ProcessPodCreationResult(&s.podState, pd, kubernetes.PSPNoPrivilegeEscalation, err)
	}
	payload := struct {
		PrivilegedEscalationRequested string
		PodSpecPath                   string
	}{
		privilegedEscalationRequested,
		filepath.Join(kubernetes.AssetsDir, "psp-azp-privileges.yaml"),
	}
	s.audit.AuditScenarioStep(description, payload, err)

	return err

}
func (s *scenarioState) someSystemExistsToPreventAKubernetesDeploymentFromRunningUsingTheAllowPrivilegeEscalationInAnExistingKubernetesCluster() error {
	err := s.runControlProbe(psp.PrivilegedEscalationIsRestricted, "PrivilegedEscalationIsRestricted")

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

//"but" same as 5.2.1

//CIS-5.2.6
func (s *scenarioState) theUserRequestedIsForTheKubernetesDeployment(requestedUser string) error {

	var runAsUser int64
	if requestedUser == "Root" {
		runAsUser = 0
	} else {
		runAsUser = 1000
	}

	pd, err := psp.CreatePODSettingSecurityContext(nil, nil, &runAsUser, s.probe)
	err = kubernetes.ProcessPodCreationResult(&s.podState, pd, kubernetes.PSPAllowedUsersGroups, err)

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) someSystemExistsToPreventAKubernetesDeploymentFromRunningAsTheRootUserInAnExistingKubernetesCluster() error {
	err := s.runControlProbe(psp.RootUserIsRestricted, "RootUserIsRestricted")

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) theKubernetesDeploymentShouldRunWithANonrootUID() error {
	err := s.runVerificationProbe(VerificationProbe{Cmd: VerifyNonRootUID, ExpectedExitCode: 1})

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

//CIS-5.2.7
func (s *scenarioState) nETRAWIsMarkedForTheKubernetesDeployment(netRawRequested string) error {

	var c []string
	if netRawRequested == "True" {
		c = make([]string, 1)
		c[0] = "NET_RAW"
	}

	pd, err := psp.CreatePODSettingCapabilities(&c, s.probe)
	err = kubernetes.ProcessPodCreationResult(&s.podState, pd, kubernetes.PSPAllowedCapabilities, err)

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) someSystemExistsToPreventAKubernetesDeploymentFromRunningWithNETRAWCapabilityInAnExistingKubernetesCluster() error {
	err := s.runControlProbe(psp.NETRawIsRestricted, "NETRAWIsRestricted")

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) iShouldNotBeAbleToPerformACommandThatRequiresNETRAWCapability() error {
	err := s.runVerificationProbe(VerificationProbe{Cmd: NetRawProbe, ExpectedExitCode: 1})

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

//CIS-5.2.8
func (s *scenarioState) additionalCapabilitiesForTheKubernetesDeployment(addCapabilities string) error {

	var c []string
	if addCapabilities == "ARE" {
		//TODO: just add net_admin for now - but is this appropriate?
		c = make([]string, 1)
		c[0] = "NET_ADMIN"
	}

	pd, err := psp.CreatePODSettingCapabilities(&c, s.probe)
	err = kubernetes.ProcessPodCreationResult(&s.podState, pd, kubernetes.PSPAllowedCapabilities, err)

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) someSystemExistsToPreventKubernetesDeploymentsWithCapabilitiesBeyondTheDefaultSetFromBeingDeployedToAnExistingKubernetesCluster() error {
	err := s.runControlProbe(psp.AllowedCapabilitiesAreRestricted, "AllowedCapabilitiesAreRestricted")

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) iShouldNotBeAbleToPerformACommandThatRequiresCapabilitiesOutsideOfTheDefaultSet() error {
	err := s.runVerificationProbe(VerificationProbe{Cmd: SpecialCapProbe, ExpectedExitCode: 2})

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

//CIS-5.2.9
func (s *scenarioState) assignedCapabilitiesForTheKubernetesDeployment(assignCapabilities string) error {

	var c []string
	if assignCapabilities == "ARE" {
		//TODO: just add net_admin for now - but is this appropriate?
		//what's the difference with 5.2.8???
		c = make([]string, 1)
		c[0] = "NET_ADMIN"
	}

	pd, err := psp.CreatePODSettingCapabilities(&c, s.probe)
	err = kubernetes.ProcessPodCreationResult(&s.podState, pd, kubernetes.PSPAllowedCapabilities, err)

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err

}
func (s *scenarioState) someSystemExistsToPreventKubernetesDeploymentsWithAssignedCapabilitiesFromBeingDeployedToAnExistingKubernetesCluster() error {
	err := s.runControlProbe(psp.AssignedCapabilitiesAreRestricted, "AssignedCapabilitiesAreRestricted")

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) iShouldNotBeAbleToPerformACommandThatRequiresAnyCapabilities() error {
	err := s.runVerificationProbe(VerificationProbe{Cmd: SpecialCapProbe, ExpectedExitCode: 2})

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

//AZ Policy - port range
func (s *scenarioState) anPortRangeIsRequestedForTheKubernetesDeployment(portRange string) error {

	var y []byte
	var err error
	description := ""
	var payload interface{}

	if portRange == "unapproved" {
		y, err = utils.ReadStaticFile(kubernetes.AssetsDir, "psp-azp-hostport-unapproved.yaml")
	} else {
		y, err = utils.ReadStaticFile(kubernetes.AssetsDir, "psp-azp-hostport-approved.yaml")
	}

	if err == nil {
		pd, err := psp.CreatePodFromYaml(y, s.probe)
		err = kubernetes.ProcessPodCreationResult(&s.podState, pd, kubernetes.PSPAllowedPortRange, err)
	}

	s.audit.AuditScenarioStep(description, payload, err)

	return err

}

func (s *scenarioState) someSystemExistsToPreventKubernetesDeploymentsWithUnapprovedPortRangeFromBeingDeployedToAnExistingKubernetesCluster() error {
	err := s.runControlProbe(psp.HostPortsAreRestricted, "HostPortsAreRestricted")

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) iShouldNotBeAbleToPerformACommandThatAccessAnUnapprovedPortRange() error {
	err := s.runVerificationProbe(VerificationProbe{Cmd: NetCat, ExpectedExitCode: 1})

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

//AZ Policy - volume type
func (s *scenarioState) anVolumeTypeIsRequestedForTheKubernetesDeployment(volumeType string) error {

	var y []byte
	var err error
	description := ""
	var payload interface{}

	if volumeType == "unapproved" {
		y, err = utils.ReadStaticFile(kubernetes.AssetsDir, "psp-azp-volumetypes-unapproved.yaml")
	} else {
		y, err = utils.ReadStaticFile(kubernetes.AssetsDir, "psp-azp-volumetypes-approved.yaml")
	}

	if err == nil {
		pd, err := psp.CreatePodFromYaml(y, s.probe)
		err = kubernetes.ProcessPodCreationResult(&s.podState, pd, kubernetes.PSPAllowedVolumeTypes, err)
	}

	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) someSystemExistsToPreventKubernetesDeploymentsWithUnapprovedVolumeTypesFromBeingDeployedToAnExistingKubernetesCluster() error {
	err := s.runControlProbe(psp.VolumeTypesAreRestricted, "VolumeTypesAreRestricted")

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

// PENDING IMPLEMENTATION
func (s *scenarioState) iShouldNotBeAbleToPerformACommandThatAccessesAnUnapprovedVolumeType() error {

	//TODO: Not sure what the test is here - if any
	return nil
}

//AZ Policy - seccomp profile
func (s *scenarioState) anSeccompProfileIsRequestedForTheKubernetesDeployment(seccompProfile string) error {

	var y []byte
	var err error
	description := ""
	var payload interface{}

	if seccompProfile == "unapproved" {
		y, err = utils.ReadStaticFile(kubernetes.AssetsDir, "psp-azp-seccomp-unapproved.yaml")
	} else if seccompProfile == "undefined" {
		y, err = utils.ReadStaticFile(kubernetes.AssetsDir, "psp-azp-seccomp-undefined.yaml")
	} else if seccompProfile == "approved" {
		y, err = utils.ReadStaticFile(kubernetes.AssetsDir, "psp-azp-seccomp-approved.yaml")
	}

	if err != nil {
		pd, err := psp.CreatePodFromYaml(y, s.probe)
		err = kubernetes.ProcessPodCreationResult(&s.podState, pd, kubernetes.PSPSeccompProfile, err)
	}

	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (s *scenarioState) someSystemExistsToPreventKubernetesDeploymentsWithoutApprovedSeccompProfilesFromBeingDeployedToAnExistingKubernetesCluster() error {
	err := s.runControlProbe(psp.SeccompProfilesAreRestricted, "SeccompProfilesAreRestricted")

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}
func (s *scenarioState) iShouldNotBeAbleToPerformASystemCallThatIsBlockedByTheSeccompProfile() error {
	err := s.runVerificationProbe(VerificationProbe{Cmd: Unshare, ExpectedExitCode: 1})

	description := ""
	var payload interface{}
	s.audit.AuditScenarioStep(description, payload, err)

	return err
}

func (p ProbeStruct) Name() string {
	return "pod_security_policy"
}

// pspProbeInitialize handles any overall Test Suite initialisation steps.  This is registered with the
// test handler as part of the init() function.
func (p ProbeStruct) ProbeInitialize(ctx *godog.TestSuiteContext) {
	ctx.BeforeSuite(func() {
		//check dependencies ...
		if psp == nil {
			// not been given one so set default
			psp = NewDefaultPSP()
		}
		psp.CreateConfigMap()
	})

	ctx.AfterSuite(func() {
		psp.DeleteConfigMap()
	})
}

// pspScenarioInitialize initialises the specific test steps.  This is essentially the creation of the test
// which reflects the tests described in the events directory.  There must be a test step registered for
// each line in the feature files. Note: Godog will output stub steps and implementations if it doesn't find
// a step / function defined.  See: https://github.com/cucumber/godog#example.
func (p ProbeStruct) ScenarioInitialize(ctx *godog.ScenarioContext) {
	ps := scenarioState{}

	ctx.BeforeScenario(func(s *godog.Scenario) {
		beforeScenario(&ps, p.Name(), s)
	})

	ctx.Step(`^a Kubernetes cluster exists which we can deploy into$`, ps.aKubernetesClusterIsDeployed)

	ctx.Step(`^a Kubernetes deployment is applied to an existing Kubernetes cluster$`, ps.aKubernetesDeploymentIsAppliedToAnExistingKubernetesCluster)

	//CIS-5.2.1
	ctx.Step(`^privileged access request is marked "([^"]*)" for the Kubernetes deployment$`, ps.privilegedAccessRequestIsMarkedForTheKubernetesDeployment)
	ctx.Step(`^some system exists to prevent a Kubernetes deployment running with privileged access in an existing Kubernetes cluster$`, ps.someControlExistsToPreventPrivilegedAccessForKubernetesDeploymentsToAnActiveKubernetesCluster)
	ctx.Step(`^I should not be able to perform a command that requires privileged access$`, ps.iShouldNotBeAbleToPerformACommandThatRequiresPrivilegedAccess)

	//CIS-5.2.2
	ctx.Step(`^hostPID request is marked "([^"]*)" for the Kubernetes deployment$`, ps.hostPIDRequestIsMarkedForTheKubernetesDeployment)
	ctx.Step(`^some system exists to prevent a Kubernetes deployment from running using the hostPID in an existing Kubernetes cluster$`, ps.someSystemExistsToPreventAKubernetesContainerFromRunningUsingTheHostPIDOnTheActiveKubernetesCluster)
	ctx.Step(`^I should not be able to perform a command that provides access to the host PID namespace$`, ps.iShouldNotBeAbleToPerformACommandThatProvidesAccessToTheHostPIDNamespace)

	//CIS-5.2.3
	ctx.Step(`^hostIPC request is marked "([^"]*)" for the Kubernetes deployment$`, ps.hostIPCRequestIsMarkedForTheKubernetesDeployment)
	ctx.Step(`^some system exists to prevent a Kubernetes deployment from running using the hostIPC in an existing Kubernetes cluster$`, ps.someSystemExistsToPreventAKubernetesDeploymentFromRunningUsingTheHostIPCInAnExistingKubernetesCluster)
	ctx.Step(`^I should not be able to perform a command that provides access to the host IPC namespace$`, ps.iShouldNotBeAbleToPerformACommandThatProvidesAccessToTheHostIPCNamespace)

	//CIS-5.2.4
	ctx.Step(`^hostNetwork request is marked "([^"]*)" for the Kubernetes deployment$`, ps.hostNetworkRequestIsMarkedForTheKubernetesDeployment)
	ctx.Step(`^some system exists to prevent a Kubernetes deployment from running using the hostNetwork in an existing Kubernetes cluster$`, ps.someSystemExistsToPreventAKubernetesDeploymentFromRunningUsingTheHostNetworkInAnExistingKubernetesCluster)
	ctx.Step(`^I should not be able to perform a command that provides access to the host network namespace$`, ps.iShouldNotBeAbleToPerformACommandThatProvidesAccessToTheHostNetworkNamespace)

	//CIS-5.2.5
	ctx.Step(`^privileged escalation is marked "([^"]*)" for the Kubernetes deployment$`, ps.privilegedEscalationIsMarkedForTheKubernetesDeployment)
	ctx.Step(`^some system exists to prevent a Kubernetes deployment from running using the allowPrivilegeEscalation in an existing Kubernetes cluster$`, ps.someSystemExistsToPreventAKubernetesDeploymentFromRunningUsingTheAllowPrivilegeEscalationInAnExistingKubernetesCluster)

	//CIS-5.2.6
	ctx.Step(`^the user requested is "([^"]*)" for the Kubernetes deployment$`, ps.theUserRequestedIsForTheKubernetesDeployment)
	ctx.Step(`^some system exists to prevent a Kubernetes deployment from running as the root user in an existing Kubernetes cluster$`, ps.someSystemExistsToPreventAKubernetesDeploymentFromRunningAsTheRootUserInAnExistingKubernetesCluster)
	ctx.Step(`^the Kubernetes deployment should run with a non-root UID$`, ps.theKubernetesDeploymentShouldRunWithANonrootUID)

	//CIS-5.2.7
	ctx.Step(`^NET_RAW is marked "([^"]*)" for the Kubernetes deployment$`, ps.nETRAWIsMarkedForTheKubernetesDeployment)
	ctx.Step(`^some system exists to prevent a Kubernetes deployment from running with NET_RAW capability in an existing Kubernetes cluster$`, ps.someSystemExistsToPreventAKubernetesDeploymentFromRunningWithNETRAWCapabilityInAnExistingKubernetesCluster)
	ctx.Step(`^I should not be able to perform a command that requires NET_RAW capability$`, ps.iShouldNotBeAbleToPerformACommandThatRequiresNETRAWCapability)

	//CIS-5.2.8
	ctx.Step(`^additional capabilities "([^"]*)" requested for the Kubernetes deployment$`, ps.additionalCapabilitiesForTheKubernetesDeployment)
	ctx.Step(`^some system exists to prevent Kubernetes deployments with capabilities beyond the default set from being deployed to an existing kubernetes cluster$`, ps.someSystemExistsToPreventKubernetesDeploymentsWithCapabilitiesBeyondTheDefaultSetFromBeingDeployedToAnExistingKubernetesCluster)
	ctx.Step(`^I should not be able to perform a command that requires capabilities outside of the default set$`, ps.iShouldNotBeAbleToPerformACommandThatRequiresCapabilitiesOutsideOfTheDefaultSet)

	//CIS-5.2.9
	ctx.Step(`^assigned capabilities "([^"]*)" requested for the Kubernetes deployment$`, ps.assignedCapabilitiesForTheKubernetesDeployment)
	ctx.Step(`^some system exists to prevent Kubernetes deployments with assigned capabilities from being deployed to an existing Kubernetes cluster$`, ps.someSystemExistsToPreventKubernetesDeploymentsWithAssignedCapabilitiesFromBeingDeployedToAnExistingKubernetesCluster)
	ctx.Step(`^I should not be able to perform a command that requires any capabilities$`, ps.iShouldNotBeAbleToPerformACommandThatRequiresAnyCapabilities)

	//AZPolicy - port range
	ctx.Step(`^an "([^"]*)" port range is requested for the Kubernetes deployment$`, ps.anPortRangeIsRequestedForTheKubernetesDeployment)
	ctx.Step(`^I should not be able to perform a command that access an unapproved port range$`, ps.iShouldNotBeAbleToPerformACommandThatAccessAnUnapprovedPortRange)
	ctx.Step(`^some system exists to prevent Kubernetes deployments with unapproved port range from being deployed to an existing Kubernetes cluster$`, ps.someSystemExistsToPreventKubernetesDeploymentsWithUnapprovedPortRangeFromBeingDeployedToAnExistingKubernetesCluster)

	//AZPolicy - volume types
	ctx.Step(`^an "([^"]*)" volume type is requested for the Kubernetes deployment$`, ps.anVolumeTypeIsRequestedForTheKubernetesDeployment)
	ctx.Step(`^I should not be able to perform a command that accesses an unapproved volume type$`, ps.iShouldNotBeAbleToPerformACommandThatAccessesAnUnapprovedVolumeType)
	ctx.Step(`^some system exists to prevent Kubernetes deployments with unapproved volume types from being deployed to an existing Kubernetes cluster$`, ps.someSystemExistsToPreventKubernetesDeploymentsWithUnapprovedVolumeTypesFromBeingDeployedToAnExistingKubernetesCluster)

	//AZPolicy - seccomp profile
	ctx.Step(`^an "([^"]*)" seccomp profile is requested for the Kubernetes deployment$`, ps.anSeccompProfileIsRequestedForTheKubernetesDeployment)
	ctx.Step(`^some system exists to prevent Kubernetes deployments without approved seccomp profiles from being deployed to an existing Kubernetes cluster$`, ps.someSystemExistsToPreventKubernetesDeploymentsWithoutApprovedSeccompProfilesFromBeingDeployedToAnExistingKubernetesCluster)
	ctx.Step(`^I should not be able to perform a system call that is blocked by the seccomp profile$`, ps.iShouldNotBeAbleToPerformASystemCallThatIsBlockedByTheSeccompProfile)

	//general - outcome
	ctx.Step(`^the operation will "([^"]*)" with an error "([^"]*)"$`, ps.theOperationWillWithAnError)
	ctx.Step(`^I should be able to perform an allowed command$`, ps.performAllowedCommand)

	ctx.AfterScenario(func(s *godog.Scenario, err error) {
		psp.TeardownPodSecurityProbe(ps.podState.PodName, p.Name())
		ps.podState.PodName = ""
		ps.podState.CreationError = nil
		coreengine.LogScenarioEnd(s)
	})

}
