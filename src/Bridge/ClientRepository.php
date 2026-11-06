<?php

namespace Idaas\Passport\Bridge;

use Laravel\Passport\Bridge\Client as PassportClient;
use Laravel\Passport\Bridge\ClientRepository as LaravelClientRepository;
use Laravel\Passport\Client as ClientModel;
use League\OAuth2\Server\Entities\ClientEntityInterface;

class ClientRepository extends LaravelClientRepository
{
    /**
     * OpenID grants are registered as "{grant}_oidc". Clients store the base grant type.
     */
    protected function fromClientModel(ClientModel $model): ClientEntityInterface
    {
        return new PassportClient(
            (string) $model->getKey(),
            $model->name,
            $this->redirectUrisFor($model),
            $model->confidential(),
            $model->getAttributes()['provider'] ?? null,
            $this->grantTypesFor($model),
        );
    }

    /**
     * @return string[]
     */
    protected function grantTypesFor(ClientModel $model): array
    {
        if ($model->application_type == null) {
            return [];
        }

        $grantTypes = $model->getAttributes()['grant_types'] ?? [];

        if (is_string($grantTypes)) {
            $decoded = json_decode($grantTypes, true);
            $grantTypes = is_array($decoded) ? $decoded : [];
        }

        if (! is_array($grantTypes)) {
            return [];
        }

        $expanded = [];

        foreach ($grantTypes as $grantType) {
            $expanded[] = $grantType;
            $expanded[] = $grantType.'_oidc';
        }

        return $expanded;
    }

    /**
     * @return string[]
     */
    protected function redirectUrisFor(ClientModel $model): array
    {
        $redirectUris = $model->getAttributes()['redirect_uris'] ?? [];

        if (is_string($redirectUris)) {
            $decoded = json_decode($redirectUris, true);
            $redirectUris = is_array($decoded)
                ? $decoded
                : ($redirectUris === '' ? [] : explode(',', $redirectUris));
        }

        return is_array($redirectUris) ? array_values($redirectUris) : [];
    }

    public function all()
    {
        return $this->clients->all();
    }

    public function findForManagement($clientId)
    {
        return $this->clients->findForManagement($clientId);
    }

    public function getRepository()
    {
        return $this->clients;
    }
}
