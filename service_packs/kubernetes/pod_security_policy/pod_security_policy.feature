@kubernetes
@pod_security_policy
@CIS-5.2
Feature: Maximise security through Pod Security Policies

  As a Cloud Security Administrator
  I want to ensure that a stringent set of Pod Security Policies are present
  So that a policy of least privilege can be enforced in order to prevent malicious attacks on my organization

#Rule: Insert tags here. ... for some reason 'Rule:' doesn't work in latest godog ..
#TODO: for 5.2.1 .. these are all 'creation', so 'deployment running' should be changed to 'deployment created'
#TODO: question .. how specific should we be on the control terminology?  e.g. should we stick with
# the below, or specific, like "And 'isPrivileged' is set to <true|false>"??
#TODO: also ... for 5.2.5, we can test to prevent creation, but what about trying to execute a cmd which reqs root?
# think we should do that, but is that a separate scenario or blend into this one?  for some this makes sense - mark with @detective?


  Background:
    Given a Kubernetes cluster is deployed
    # TODO did have When a Kubernetes deployment is applied to an existing Kubernetes cluster, but it was just return nil.


  @preventative @CIS-5.2.1
  Scenario Outline: Prevent a deployment from running with privileged access
    # TODO rename this, what the step actually does is create a Pod with Privileged Access (or not)
    And privileged access request is marked "<privileged access requested>" for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    # TODO Would reverse these - "And I should not, but I should..."
    But I should not be able to perform a command that requires privileged access
    And I should be able to perform an allowed command

    Examples:
      | privileged access requested | RESULT  | ERRORMESSAGE                                |
      | True                        | Fail    | Containers with privileged access can't run |
      | False                       | Succeed | No error would show                         |
      | Not Defined                 | Succeed | No error would show                         |


  @preventative @CIS-5.2.2
  Scenario Outline: Prevent a deployment from running with the hostPID
    And hostPID request is marked "<HostPID requested>" for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    But I should not be able to perform a command that provides access to the host PID namespace
    And I should be able to perform an allowed command

    Examples:
      | HostPID requested | RESULT  | ERRORMESSAGE                      |
      | True              | Fail    | Containers cant run using hostPID |
      | False             | Succeed |                                   |
      | Not Defined       | Succeed |                                   |


  @preventative @CIS-5.2.3
  Scenario Outline: Prevent a deployment from running with the hostIPC flag.
    And hostIPC request is marked "<hostIPC access is requested>" for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    But I should not be able to perform a command that provides access to the host IPC namespace
    And I should be able to perform an allowed command

    Examples:
      | hostIPC access is requested | RESULT  | ERRORMESSAGE                             |
      | True                        | Fail    | Containers with hostIPC access can't run |
      | False                       | Succeed | No error would show                      |
      | Not defined                 | Succeed | No error would show                      |


  @preventative @CIS-5.2.4
  Scenario Outline: Prevent a deployment from running with the hostNetwork flag.
    And hostNetwork request is marked "<hostNetwork access is requested>" for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    But I should not be able to perform a command that provides access to the host network namespace
    And I should be able to perform an allowed command

    Examples:
      | hostNetwork access is requested | RESULT  | ERRORMESSAGE                                 |
      | True                            | Fail    | Containers with hostNetwork access can't run |
      | False                           | Succeed | No error would show                          |
      | Not defined                     | Succeed | No error would show                          |


  @preventative @CIS-5.2.5
  Scenario Outline: Prevent a deployment from running with the allowPrivilegeEscalation flag
    And privileged escalation is marked "<AllowPrivilegeEscalation requested>" for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    But I should not be able to perform a command that requires privileged access
    And I should be able to perform an allowed command

    Examples:
      | AllowPrivilegeEscalation requested | RESULT  | ERRORMESSAGE                                                |
      | True                               | Fail    | Containers cant run using the allowPrivilegeEscalation flag |
      | False                              | Succeed | No error would show                                         |
      | Not Defined                        | Succeed | No error would show                                         |


  @preventative @CIS-5.2.6
  Scenario Outline: Prevent a deployment from running as the root user
    And the user requested is "<requested user>" for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    And the Kubernetes deployment should run with a non-root UID
    And I should be able to perform an allowed command

    Examples:
      | requested user | RESULT  | ERRORMESSAGE                |
      | Root           | Fail    | Containers cant run as root |
      | Non-Root       | Succeed |                             |
      | Not Defined    | Succeed |                             |


  @preventative @CIS-5.2.7
  Scenario Outline: Prevent deployments from running with the NET_RAW capability.
    And  NET_RAW is marked "<NET_RAW requested>" for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    But I should not be able to perform a command that requires NET_RAW capability
    And I should be able to perform an allowed command

    Examples:
      | NET_RAW requested | RESULT  | ERRORMESSAGE                                  |
      | True              | Fail    | Containers cant run with NET_RAW capabilities |
      | False             | Succeed |                                               |
      | Not Defined       | Succeed |                                               |


  @preventative @CIS-5.2.8
  Scenario Outline: Prevent container running with capabilities beyond the default set.
    And additional capabilities "<requested>" requested for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    But I should not be able to perform a command that requires capabilities outside of the default set
    And I should be able to perform an allowed command

    Examples:
      | requested   | RESULT  | ERRORMESSAGE                                 |
      | ARE         | Fail    | Containers can't run with added capabilities |
      | ARE NOT     | Succeed |                                              |
      | Not Defined | Succeed |                                              |


  @preventative @CIS-5.2.9
  Scenario Outline: Prevent deployments from running with assigned capabilities.
    And assigned capabilities "<requested>" requested for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    But I should not be able to perform a command that requires any capabilities
    And I should be able to perform an allowed command

    Examples:
      | requested   | RESULT  | ERRORMESSAGE                                            |
      | ARE         | Fail    | Containers with assigned capabilities can't be deployed |
      | ARE NOT     | Succeed |                                                         |
      | Not defined | Succeed |                                                         |


    # @preventative @AZP-0.1
    # Scenario Outline: Prevent deployments from accessing unapproved port range
    # 	And an "<requested>" port range is requested for the Kubernetes deployment
    # 	Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    # 	But I should not be able to perform a command that access an unapproved port range
    # 	And I should be able to perform an allowed command

    # 	Examples:
    # 		| requested 	| RESULT 	| ERRORMESSAGE							|
    # 		| unapproved  	| Fail  	| Cannot access unapproved port range	|
    # 		| approved		| Succeed	|									  	|
    # 		| not defined	| Succeed	|										|


  @preventative @AZP-0.2
  Scenario Outline: Prevent deployments from accessing unapproved volume types
    And an "<requested>" volume type is requested for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    But I should not be able to perform a command that accesses an unapproved volume type
    And I should be able to perform an allowed command

    Examples:
      | requested   | RESULT  | ERRORMESSAGE                         |
      | unapproved  | Fail    | Cannot access unapproved volume type |
      | approved    | Succeed |                                      |
      | not defined | Succeed |                                      |


  @preventative @AZP-0.3
  Scenario Outline: Prevent deployments from running without approved seccomp profile
    And an "<requested>" seccomp profile is requested for the Kubernetes deployment
    Then the operation will "<RESULT>" with an error "<ERRORMESSAGE>"
    But I should not be able to perform a system call that is blocked by the seccomp profile
    And I should be able to perform an allowed command

    Examples:
      | requested  | RESULT  | ERRORMESSAGE                              |
      | unapproved | Fail    | Cannot request unapproved seccomp profile |
      | approved   | Succeed | no error                                  |
      | undefined  | Fail    | Approved seccomp profile required         |
