<?php

namespace Idaas\Passport\Http\Controllers;

use Idaas\OpenID\RequestTypes\AuthenticationRequest;
use Idaas\Passport\PassportConfig;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Laravel\Passport\Bridge\User;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\AuthorizationViewResponse;
use Laravel\Passport\Http\Controllers\AuthorizationController as LaravelAuthorizationController;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Nyholm\Psr7\Response as Psr7Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Response;

class AuthorizationController extends LaravelAuthorizationController
{
    /**
     * In contrast with Laravel Passport, this authorize method can be invoked when the user has not been authenticated.
     * This is because OpenID Connect determines how the user should be authenticated.
     */
    public function authorize(
        ServerRequestInterface $psrRequest,
        Request $request,
        ResponseInterface $psrResponse,
        AuthorizationViewResponse $viewResponse,
    ): Response|AuthorizationViewResponse {
        return $this->withErrorHandling(function () use ($psrRequest, $request, $psrResponse) {
            $authorizationRequest = $this->server->validateAuthorizationRequest($psrRequest);
            $authenticateResponse = $this->doAuthenticate($psrRequest, $authorizationRequest);

            if ($authenticateResponse == null) {
                $authenticateResponse = $this->continueAuthorize($authorizationRequest, $request, $psrResponse);
            }

            return $authenticateResponse;
        }, $this->usesFragmentResponse($psrRequest->getQueryParams()['response_type'] ?? null));
    }

    /**
     * Implicit and hybrid response types (token, id_token) return their response in the URL fragment.
     */
    protected function usesFragmentResponse(?string $responseType): bool
    {
        return array_intersect(explode(' ', (string) $responseType), ['token', 'id_token']) !== [];
    }

    public function continueAuthorize(
        ?AuthorizationRequestInterface $authRequest,
        Request $request,
        ResponseInterface $psrResponse
    ) {
        if ($authRequest == null) {
            $authRequest = $request->session()->get('authRequest');

            if (is_string($authRequest)) {
                $authRequest = unserialize($authRequest);
            }
        }

        if (! $authRequest instanceof AuthorizationRequestInterface) {
            throw OAuthServerException::invalidRequest('unknown', 'No authorization request found. Seems like a cookie problem.');
        }

        $user = $request->user();
        $client = $this->clients->find($authRequest->getClient()->getIdentifier());
        $scopes = $this->parseScopes($authRequest);

        if ($user !== null && ($client->skipsAuthorization($user, $scopes) || $this->hasExactGrantedScopes($user, $client, $scopes))) {
            $authRequest->setUser(new User((string) $user->getAuthIdentifier()));

            return $this->approveRequest($authRequest, $psrResponse);
        }

        return $this->returnError($authRequest, $request);
    }

    /**
     * @param  \Laravel\Passport\Scope[]  $scopes
     */
    protected function hasExactGrantedScopes(Authenticatable $user, Client $client, array $scopes): bool
    {
        $token = $client->tokens()
            ->where('user_id', $user->getAuthIdentifier())
            ->where('revoked', false)
            ->where('expires_at', '>', now())
            ->latest('expires_at')
            ->first();

        return $token && $token->scopes === collect($scopes)->pluck('id')->all();
    }

    protected function approveRequest(AuthorizationRequestInterface $authRequest, ResponseInterface $psrResponse): Response
    {
        $authRequest->setAuthorizationApproved(true);

        return $this->withErrorHandling(
            fn () => $this->convertResponse(
                $this->server->completeAuthorizationRequest($authRequest, $psrResponse)
            ),
            in_array($authRequest->getGrantTypeId(), ['implicit', 'implicit_oidc'], true)
        );
    }

    public function returnError(AuthorizationRequestInterface $authorizationRequest, Request $request)
    {
        $clientUris = Arr::wrap($authorizationRequest->getClient()->getRedirectUri());

        if (! in_array($uri = $authorizationRequest->getRedirectUri(), $clientUris)) {
            $uri = Arr::first($clientUris);
        }

        if ($authorizationRequest instanceof AuthenticationRequest && $authorizationRequest->getResponseMode() == 'web_message') {
            return (new WebMessageResponse())->setData([
                'redirect_uri' => $uri,
                'error' => 'access_denied',
                'state' => $authorizationRequest->getState(),
            ])->generateHttpResponse(new Psr7Response());
        }

        $separator = in_array($authorizationRequest->getGrantTypeId(), ['implicit', 'implicit_oidc'], true) ? '#' : '?';
        $uri = $uri.$separator.'error=access_denied&state='.$authorizationRequest->getState();

        return $this->withErrorHandling(function () use ($uri) {
            throw OAuthServerException::accessDenied(null, $uri);
        });
    }

    public function doAuthenticate(ServerRequestInterface $psrRequest, $authorizationRequest)
    {
        return resolve(PassportConfig::class)
            ->doAuthenticationResponse(
                AuthenticationRequest::fromAuthorizationRequest($authorizationRequest)
            );
    }
}
