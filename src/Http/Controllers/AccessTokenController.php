<?php

namespace Idaas\Passport\Http\Controllers;

use Closure;
use Idaas\Passport\Passport;
use Laravel\Passport\Exceptions\OAuthServerException;
use Laravel\Passport\Http\Controllers\AccessTokenController as ControllersAccessTokenController;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Exception\OAuthServerException as LeagueException;

class AccessTokenController extends ControllersAccessTokenController
{
    use CryptTrait;

    protected function withErrorHandling(Closure $callback, bool $useFragment = false)
    {
        try {
            return $callback();
        } catch (LeagueException $e) {
            if ($e->getHint() === 'Authorization code has been revoked') {
                $this->revokeTokensIssuedForReusedAuthorizationCode();
            }

            throw new OAuthServerException($e, $useFragment);
        }
    }

    /**
     * A reused authorization code already fails the token request. Revoke the access
     * token that was issued the first time the code was exchanged.
     */
    protected function revokeTokensIssuedForReusedAuthorizationCode(): void
    {
        $encryptedAuthCode = $_POST['code'] ?? null;

        if (! is_string($encryptedAuthCode) || $encryptedAuthCode === '') {
            return;
        }

        $this->setEncryptionKey(Passport::tokenEncryptionKey(app('encrypter')));
        $authCodePayload = json_decode($this->decrypt($encryptedAuthCode));

        if (! isset($authCodePayload->user_id)) {
            return;
        }

        Passport::token()->where('user_id', $authCodePayload->user_id)->update(['revoked' => true]);
    }
}
