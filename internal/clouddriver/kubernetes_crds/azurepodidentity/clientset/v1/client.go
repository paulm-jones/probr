package v1

import (
	aadpodv1 "github.com/Azure/aad-pod-identity/pkg/apis/aadpodidentity/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

type AzureBindingClientInterface interface {
	AzureIdentityBindings(namespace string) AzureIdentityBindingInterface
}

type AzureBindingClient struct {
	restClient rest.Interface
}

func NewForConfig(c *rest.Config) (*AzureBindingClient, error) {
	config := *c
	config.ContentConfig.GroupVersion = &schema.GroupVersion{Group: aadpodv1.CRDGroup, Version: aadpodv1.CRDVersion}
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	config.UserAgent = rest.DefaultKubernetesUserAgent()

	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}

	return &AzureBindingClient{restClient: client}, nil
}

func (c *AzureBindingClient) AzureIdentityBindings(namespace string) AzureIdentityBindingInterface {
	return &azureIdentityBindingClient{
		restClient: c.restClient,
		ns:         namespace,
	}
}
