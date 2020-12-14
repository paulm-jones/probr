@probes/kubernetes
@probes/kubernetes/general
@standard/cis
@standard/cis/gke
@csp/any
Feature: General Cluster Security Configurations
  As a Security Auditor
  I want to ensure that Kubernetes clusters have general security configurations in place
  So that no general cluster vulnerabilities can be exploited

  @probes/kubernetes/general/1.2
  @control_type/inspection
  @standard/cis/gke/6.10.1
  @standard/citihub/CHC2-ITS115
  Scenario: Ensure Kubernetes Web UI is disabled

  The Kubernetes Web UI (Dashboard) has been a historical source of vulnerability and should only be deployed when necessary.

    Given a Kubernetes cluster is deployed
    Then the Kubernetes Web UI is disabled