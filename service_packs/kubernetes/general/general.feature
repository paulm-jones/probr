@probes/kubernetes
@probes/kubernetes/general
@standard/cis
@standard/cis/gke
@csp/any
Feature: General Cluster Security Configurations
  As a Security Auditor
  I want to ensure that Kubernetes clusters have general security configurations in place
  So that no general cluster vulnerabilities can be exploited

  Background:
    Given a Kubernetes cluster is deployed

  #TODO: should probably move 5.1.3 into the IAM section??
  @probes/kubernetes/general/1.0 @control_type/inspection @standard/cis/gke/5.1.3 @standard/citihub/CHC2-IAM105
  Scenario Outline: Minimise wildcards in Roles and Cluster Roles

  Kubernetes roles provide access to resources. Using wildcards does not adhere to the security principle of least privilege.
  Other than known system-assigned and well understood role definitions (which are configurable in Probr), we should not expect to use wildcards.

    When I inspect the "<rolelevel>" that are configured
    Then I should only find wildcards in known and authorised configurations

    Examples:
      | rolelevel     |
      | Roles         |
      | Cluster Roles |


  @probes/kubernetes/general/1.1 @control_type/inspection @standard/cis/gke/5.6.3
  # TODO Perhaps we need an opinionated view of what good looks like here
  # For example this test arguably shouldn't pass if I provide `securityContext: allowPrivilegeEscalation: true`
  # Arguably could move into PSP Feature
  # #OPA #BestPractice
  # TODO PJITREVIEW remove for now
  Scenario: Ensure Security Contexts are enforced

  A Security Context defines privilege and access control settings for a Pod or Container.
  Settings include AppArmor, Secure Computing Profiles and Privilege Escalation.

    When I attempt to create a Pod which does not have a Security Context
    Then the deployment is rejected


  @probes/kubernetes/general/1.2 @control_type/inspection @standard/cis/gke/6.10.1 @standard/citihub/CHC2-ITS115
  Scenario: Ensure Kubernetes Web UI is disabled

  The Kubernetes Web UI (Dashboard) has been a historical source of vulnerability and should only be deployed when necessary.

    Then the Kubernetes Web UI is disabled