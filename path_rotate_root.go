package azuresecrets

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	rotateRootPath = "rotate-root"
)

func pathRotateRootCredentials(b *azureSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: rotateRootPath,
		Fields:  map[string]*framework.FieldSchema{},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathRotateRootCredentialsUpdate,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback:                    b.pathRotateRootCredentialsUpdate,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		HelpSynopsis: "Request to rotate the root credentials Vault uses for managing Azure.",
		HelpDescription: "This path attempts to rotate the root credentials of the administrator account " +
			"used by Vault to manage Azure.",
	}
}

func (b *azureSecretBackend) pathRotateRootCredentialsUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	duration := (time.Hour * 24) * 6

	_, password, err := client.addAppPassword(ctx, b.settings.ObjectID, duration)
	if err != nil {
		return nil, err
	}

	config.ClientSecret = password

	err = b.saveConfig(ctx, config, req.Storage)

	// Respond with a 204.
	return nil, err
}
