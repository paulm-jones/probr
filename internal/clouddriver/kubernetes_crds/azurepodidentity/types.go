package azurepodidentity

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// AzureIdentityBinding brings together the spec of matching pods and the identity which they can use.
//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type AzureIdentityBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AzureIdentityBindingSpec   `json:"spec"`
	Status AzureIdentityBindingStatus `json:"status"`
}

// AzureIdentityBindingList contains a list of AzureIdentityBindings.
//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type AzureIdentityBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []AzureIdentityBinding `json:"items"`
}

// AzureIdentityBindingSpec matches the pod with the Identity.
// Used to indicate the potential matches to look for between the pod/deployment
// and the identities present.
type AzureIdentityBindingSpec struct {
	metav1.ObjectMeta `json:"metadata,omitempty"`
	AzureIdentity     string `json:"azureidentity"`
	Selector          string `json:"selector"`
	// Weight is used to figure out which of the matching identities would be selected.
	Weight int `json:"weight"`
}

// AzureIdentityBindingStatus contains the status of an AzureIdentityBinding.
type AzureIdentityBindingStatus struct {
	metav1.ObjectMeta `json:"metadata,omitempty"`
	AvailableReplicas int32 `json:"availableReplicas"`
}
