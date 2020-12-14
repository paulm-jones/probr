@probes/kubernetes
@probes/kubernetes/pod_security_policy
@category/pod_security_policy
@standard/cis
@standard/cis/gke
@standard/cis/gke/5
@standard/cis/gke/5.2
@standard/citihub
@standard/citihub/CHC2-IAM105
@csp/any
Feature: Maximise security through Pod Security Policies

  As a Cloud Security Administrator
  I want to ensure that a stringent set of Pod Security Policies are present
  So that a policy of least privilege can be enforced in order to prevent malicious attacks on my organization

  Background:
    Given a Kubernetes cluster is deployed



#Rule: Insert tags here. ... for some reason 'Rule:' doesn't work in latest godog ..
#TODO: for 5.2.1 .. these are all 'creation', so 'deployment running' should be changed to 'deployment created'
#TODO: question .. how specific should we be on the control terminology?  e.g. should we stick with
# the below, or specific, like "And 'isPrivileged' is set to <true|false>"??
#TODO: also ... for 5.2.5, we can test to prevent creation, but what about trying to execute a cmd which reqs root?
# think we should do that, but is that a separate scenario or blend into this one?  for some this makes sense - mark with @detective?

  @probes/kubernetes/pod_security_policy/1.0
    @control_type/preventative
    @standard/cis/gke/5.2.1
  Scenario Outline: Prevent a deployment from running with privileged access

  Pods that request Privileged mode (using the `privileged` flag on the security context of the container spec
  will get operating system administrative capabilities - almost the same privileges that are accessible outside of a
  container.

  See https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privileged

    And I request creation of a Pod with Privileged mode "<privileged access requested>"
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    And I should be able to perform an allowed command
    But I should not be able to perform a command that requires privileged access

    Examples:
      | privileged access requested | RESULT  | ERRORMESSAGE                                |
      | True                        | Fail    | Containers with privileged access can't run |
      | False                       | Succeed | No error would show                         |
      | Not Defined                 | Succeed | No error would show                         |


  @probes/kubernetes/pod_security_policy/1.1
    @control_type/preventative
    @standard/cis/gke/5.2.2
  Scenario Outline: Prevent a deployment from running with the hostPID

  HostPID controls whether a Pod's containers can share the host process ID namespace. When paired with ptrace, this
  can be used to escalate privileges outside of the container.

  See https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces.

    And I request creation of a Pod with shared host process ID namespace "<HostPID requested>"
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    And I should be able to perform an allowed command
    But I should not be able to perform a command that provides access to the host PID namespace

    Examples:
      | HostPID requested | RESULT  | ERRORMESSAGE                        |
      | True              | Fail    | Containers cannot run using hostPID |
      | False             | Succeed |                                     |
      | Not Defined       | Succeed |                                     |


  @probes/kubernetes/pod_security_policy/1.2
    @control_type/preventative
    @standard/cis/gke/5.2.3
  Scenario Outline: Prevent a deployment from running with the hostIPC flag.

  HostIPC controls whether a Pod's containers can share the host IPC namespace, allowing container processes to
  communicate with other processes on the host.

  See https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces.

    And I request creation of a Pod with shared host IPC namespace "<hostIPC access is requested>"
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    And I should be able to perform an allowed command
    But I should not be able to perform a command that provides access to the host IPC namespace

    Examples:
      | hostIPC access is requested | RESULT  | ERRORMESSAGE                             |
      | True                        | Fail    | Containers with hostIPC access can't run |
      | False                       | Succeed | No error would show                      |
      | Not defined                 | Succeed | No error would show                      |


  @probes/kubernetes/pod_security_policy/1.3
    @control_type/preventative
    @standard/cis/gke/5.2.4
  Scenario Outline: Prevent a deployment from running with the hostNetwork flag.

  The HostNetwork flag controls whether the pod may use the node network namespace. Doing so gives the pod access
  to the loopback device, services listening on localhost, and could be used to snoop on network activity of other
  pods on the same node.

  See https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces

    And I request creation of a Pod with shared host network flag "<hostNetwork access is requested>"
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    And I should be able to perform an allowed command
    But I should not be able to perform a command that provides access to the host network namespace

    Examples:
      | hostNetwork access is requested | RESULT  | ERRORMESSAGE                                 |
      | True                            | Fail    | Containers with hostNetwork access can't run |
      | False                           | Succeed | No error would show                          |
      | Not defined                     | Succeed | No error would show                          |


  @probes/kubernetes/pod_security_policy/1.4
    @control_type/preventative
    @standard/cis/gke/5.2.5
  Scenario Outline: Prevent a deployment from running with the allowPrivilegeEscalation flag

  `AllowPrivilegeEscalation` controls whether a process can gain more privileges than its parent.

  See https://kubernetes.io/docs/tasks/configure-pod-container/security-context/

    And I request creation of a Pod with Privilege Escalation "<AllowPrivilegeEscalation requested>"
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    And I should be able to perform an allowed command
    But I should not be able to perform a command that requires privileged access

    Examples:
      | AllowPrivilegeEscalation requested | RESULT  | ERRORMESSAGE                                                |
      | True                               | Fail    | Containers cant run using the allowPrivilegeEscalation flag |
      | False                              | Succeed | No error would show                                         |
      | Not Defined                        | Succeed | No error would show                                         |


  @probes/kubernetes/pod_security_policy/1.5
    @control_type/preventative
    @standard/cis/gke/5.2.6
  Scenario Outline: Prevent a deployment from running as the root user

  The root user should be avoided in order to ensure least privilege.

    And the user requested is "<requested user>" for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    And the Kubernetes deployment should run with a non-root UID
    And I should be able to perform an allowed command

    Examples:
      | requested user | RESULT  | ERRORMESSAGE                  |
      | Root           | Fail    | Containers cannot run as root |
      | Non-Root       | Succeed |                               |
      | Not Defined    | Succeed |                               |


  @probes/kubernetes/pod_security_policy/1.6
    @control_type/preventative
    @standard/cis/gke/5.2.7
  Scenario Outline: Prevent deployments from running with the NET_RAW capability.

  The `CAP_NET_RAW` Linux kernel capability can be used maliciously, including in the exploit of a vulnerability
  that may allow container escape and root privileges on the host node.

    See for example https://cloud.google.com/kubernetes-engine/docs/security-bulletins#gcp-2020-012.

    And  NET_RAW is marked "<NET_RAW requested>" for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    And I should be able to perform an allowed command
    But I should not be able to perform a command that requires NET_RAW capability

    Examples:
      | NET_RAW requested | RESULT  | ERRORMESSAGE                                    |
      | True              | Fail    | Containers cannot run with NET_RAW capabilities |
      | False             | Succeed |                                                 |
      | Not Defined       | Succeed |                                                 |


  @probes/kubernetes/pod_security_policy/1.7
    @control_type/preventative
    @standard/cis/gke/5.2.8
  Scenario Outline: Prevent container running with capabilities beyond the default set.

    And additional capabilities "<requested>" requested for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    And I should be able to perform an allowed command
    But I should not be able to perform a command that requires capabilities outside of the default set

    Examples:
      | requested   | RESULT  | ERRORMESSAGE                                 |
      | ARE         | Fail    | Containers can't run with added capabilities |
      | ARE NOT     | Succeed |                                              |
      | Not Defined | Succeed |                                              |


  @probes/kubernetes/pod_security_policy/1.8
    @control_type/preventative
    @standard/cis/gke/5.2.9
  Scenario Outline: Prevent deployments from running with assigned capabilities.

    And assigned capabilities "<requested>" requested for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    And I should be able to perform an allowed command
    But I should not be able to perform a command that requires any capabilities

    Examples:
      | requested   | RESULT  | ERRORMESSAGE                                            |
      | ARE         | Fail    | Containers with assigned capabilities can't be deployed |
      | ARE NOT     | Succeed |                                                         |
      | Not defined | Succeed |                                                         |


  @probes/kubernetes/pod_security_policy/1.10
    @control_type/preventative
  Scenario Outline: Prevent deployments from accessing unapproved volume types

    And an "<requested>" volume type is requested for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    And I should be able to perform an allowed command
    But I should not be able to perform a command that accesses an unapproved volume type

    Examples:
      | requested   | RESULT  | ERRORMESSAGE                         |
      | unapproved  | Fail    | Cannot access unapproved volume type |
      | approved    | Succeed |                                      |
      | not defined | Succeed |                                      |


  @probes/kubernetes/pod_security_policy/1.11
    @control_type/preventative
  Scenario Outline: Prevent deployments from running without approved seccomp profile

    And an "<requested>" seccomp profile is requested for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    And I should be able to perform an allowed command
    But I should not be able to perform a system call that is blocked by the seccomp profile

    Examples:
      | requested  | RESULT  | ERRORMESSAGE                              |
      | unapproved | Fail    | Cannot request unapproved seccomp profile |
      | approved   | Succeed | no error                                  |
      | undefined  | Fail    | Approved seccomp profile required         |