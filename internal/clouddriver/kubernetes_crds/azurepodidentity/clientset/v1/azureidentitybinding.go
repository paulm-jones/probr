package v1

import (
	"context"
	"github.com/citihub/probr/internal/clouddriver/kubernetes_crds/azurepodidentity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

type AzureIdentityBindingInterface interface {
	List(opts metav1.ListOptions) (*azurepodidentity.AzureIdentityBindingList, error)
	Get(name string, options metav1.GetOptions) (*azurepodidentity.AzureIdentityBinding, error)
	Create(*azurepodidentity.AzureIdentityBinding) (*azurepodidentity.AzureIdentityBinding, error)
}

type azureIdentityBindingClient struct {
	restClient rest.Interface
	ns         string
}

func (c *azureIdentityBindingClient) List(opts metav1.ListOptions) (*azurepodidentity.AzureIdentityBindingList, error) {
	result := azurepodidentity.AzureIdentityBindingList{}
	ctx := context.Background()
	err := c.restClient.
		Get().
		Namespace(c.ns).
		Resource("azureidentitybindings").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do(ctx).
		Into(&result)

	return &result, err
}

func (c *azureIdentityBindingClient) Get(name string, opts metav1.GetOptions) (*azurepodidentity.AzureIdentityBinding, error) {
	result := azurepodidentity.AzureIdentityBinding{}
	ctx := context.Background()
	err := c.restClient.
		Get().
		Namespace(c.ns).
		Resource("azureidentitybindings").
		Name(name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Do(ctx).
		Into(&result)

	return &result, err
}

func (c *azureIdentityBindingClient) Create(binding *azurepodidentity.AzureIdentityBinding) (*azurepodidentity.AzureIdentityBinding, error) {
	result := azurepodidentity.AzureIdentityBinding{}
	ctx := context.Background()
	err := c.restClient.
		Post().
		Namespace(c.ns).
		Resource("azureidentitybindings").
		Body(binding).
		Do(ctx).
		Into(&result)

	return &result, err
}
