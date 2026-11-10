<?php

namespace Idaas\Passport\Guards;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Http\Request;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Guards\TokenGuard as GuardsTokenGuard;
use Laravel\Passport\PassportUserProvider;
use League\OAuth2\Server\ResourceServer;

class TokenGuard extends GuardsTokenGuard
{
    public function __construct(
        ResourceServer $server,
        PassportUserProvider $provider,
        ClientRepository $clients,
        Encrypter $encrypter,
        Request $request
    ) {
        parent::__construct($server, $provider, $clients, $encrypter, $request);
    }

    public function user(): ?Authenticatable
    {
        $result = parent::user();

        /**
         * Support for https://tools.ietf.org/id/draft-ietf-oauth-v2-bearer-00.html#body-param
         */
        if (($access_token = $this->request->input('access_token')) != null) {
            $this->request->headers->set('Authorization', 'Bearer '.$access_token);
            $result = $this->user = $this->authenticateViaBearerToken();
        }

        return $result;
    }
}
