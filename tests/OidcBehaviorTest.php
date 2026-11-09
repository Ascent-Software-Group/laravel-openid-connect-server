<?php

namespace IdaasPassportTests;

use Idaas\Passport\Http\Controllers\AccessTokenController;
use Idaas\Passport\Http\Controllers\AuthorizationController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptTrait;
use PHPUnit\Framework\Attributes\DataProvider;

class OidcBehaviorTest extends TestCase
{
    use CryptTrait;

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../vendor/laravel/passport/database/migrations');
    }

    public function testOidcRoutesTakePrecedenceOverPassportRoutes()
    {
        $routes = $this->app['router']->getRoutes();

        $this->assertStringStartsWith(
            AuthorizationController::class,
            ltrim($routes->match(Request::create('/oauth/authorize', 'GET'))->getActionName(), '\\')
        );
        $this->assertStringStartsWith(
            AccessTokenController::class,
            ltrim($routes->match(Request::create('/oauth/token', 'POST'))->getActionName(), '\\')
        );
    }

    public function testOidcMigrationsAreLoaded()
    {
        $this->assertTrue(Schema::hasTable('oidc_clients'));
        $this->assertTrue(Schema::hasTable('oidc_personal_access_clients'));
    }

    #[DataProvider('responseTypes')]
    public function testFragmentResponsesAreUsedForImplicitResponseTypes(?string $responseType, bool $expected)
    {
        $controller = new class (
            $this->app->make(AuthorizationServer::class),
            $this->app['auth']->guard('web'),
            $this->app->make(ClientRepository::class)
        ) extends AuthorizationController {
            public function exposedUsesFragmentResponse(?string $responseType): bool
            {
                return $this->usesFragmentResponse($responseType);
            }
        };

        $this->assertSame($expected, $controller->exposedUsesFragmentResponse($responseType));
    }

    public static function responseTypes(): array
    {
        return [
            'code' => ['code', false],
            'missing' => [null, false],
            'token' => ['token', true],
            'id_token' => ['id_token', true],
            'id_token token' => ['id_token token', true],
            'code id_token' => ['code id_token', true],
        ];
    }

    public function testReusedAuthorizationCodeOnlyRevokesTheSameClientsTokens()
    {
        $this->createToken('reused-client-token', 'user-1', 'client-1');
        $this->createToken('other-client-token', 'user-1', 'client-2');
        $this->createToken('other-user-token', 'user-2', 'client-1');

        $this->setEncryptionKey(Passport::tokenEncryptionKey($this->app['encrypter']));
        $_POST['code'] = $this->encrypt(json_encode(['user_id' => 'user-1', 'client_id' => 'client-1']));

        $controller = new class ($this->app->make(AuthorizationServer::class)) extends AccessTokenController {
            public function exposedRevoke(): void
            {
                $this->revokeTokensIssuedForReusedAuthorizationCode();
            }
        };
        $controller->exposedRevoke();

        unset($_POST['code']);

        $this->assertTrue(Passport::token()->find('reused-client-token')->revoked);
        $this->assertFalse(Passport::token()->find('other-client-token')->revoked);
        $this->assertFalse(Passport::token()->find('other-user-token')->revoked);
    }

    protected function createToken(string $id, string $userId, string $clientId): void
    {
        Passport::token()->forceFill([
            'id' => $id,
            'user_id' => $userId,
            'client_id' => $clientId,
            'scopes' => [],
            'revoked' => false,
        ])->save();
    }
}
