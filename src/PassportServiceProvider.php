<?php

namespace Idaas\Passport;

use DateInterval;
use Idaas\OpenID\Grant\AuthCodeGrant;
use Idaas\OpenID\Grant\ImplicitGrant;
use Idaas\OpenID\Repositories\ClaimRepositoryInterface;
use Idaas\OpenID\Repositories\UserRepositoryInterface;
use Idaas\OpenID\ResponseTypes\BearerTokenResponse;
use Idaas\OpenID\Session;
use Idaas\Passport\Bridge\AccessTokenRepository;
use Idaas\OpenID\Repositories\AccessTokenRepositoryInterface;
use Idaas\Passport\Bridge\ClaimRepository;
use Idaas\Passport\Bridge\UserRepository;
use Idaas\Passport\Guards\TokenGuard;
use Idaas\Passport\Http\Controllers\AuthorizationController;
use Idaas\Passport\Model\Client;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Bridge\AccessTokenRepository as BridgeAccessTokenRepository;
use Laravel\Passport\Bridge\AuthCodeRepository;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Bridge\ScopeRepository;
use Laravel\Passport\ClientRepository as PassportClientRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider as LaravelPassportServiceProvider;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\ResourceServer;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Illuminate\Support\Facades\Auth;
use Laravel\Passport\Guards\TokenGuard as PassportTokenGuard;
use Laravel\Passport\PassportUserProvider;

class PassportServiceProvider extends LaravelPassportServiceProvider
{
    protected function getClientModel()
    {
        return Client::class;
    }

    public function boot(): void
    {
        Passport::useClientModel($this->getClientModel());
        // Passport::useTokenModel()

        parent::boot();

        $this->registerMigrations();

        $this->app->bindIf(ClaimRepositoryInterface::class, ClaimRepository::class);
        $this->app->bindIf(UserRepositoryInterface::class, UserRepository::class);
        
        $this->app->singleton(AccessTokenRepositoryInterface::class, function ($app) {
            return $this->app->make(AccessTokenRepository::class);
        });
        $this->app->singleton(BridgeAccessTokenRepository::class, function ($app) {
            return $app->make(AccessTokenRepositoryInterface::class);
        });

        $this->publishes(
            [
                __DIR__ . '/../examples/App/User.php' => app_path('User.php'),
                __DIR__ . '/../examples/App/Providers/AuthServiceProvider.php' =>
                app_path('Providers/AuthServiceProvider.php'),
                __DIR__ . '/../examples/config/auth.php' =>
                config_path('auth.php'),
            ]
        );
    }

    protected function makeCryptKey(string $type): CryptKey
    {
        if ($type == 'private') {
            return resolve(KeyRepository::class)->getPrivateKey();
        }

        return resolve(KeyRepository::class)->getPublicKey();
    }

    protected function registerResourceServer(): void
    {
        $this->app->singleton(ResourceServer::class, function () {
            // TODO: consider using AdvancedResourceServer
            return new ResourceServer(
                $this->app->make(Bridge\AccessTokenRepository::class),
                $this->makeCryptKey('public')
            );
        });
    }

    public function makeAuthorizationServer(?ResponseTypeInterface $responseType = null): AuthorizationServer
    {
        $server = new AuthorizationServer(
            $this->app->make(Bridge\ClientRepository::class),
            $this->app->make(Bridge\AccessTokenRepository::class),
            $this->app->make(ScopeRepository::class),
            $this->makeCryptKey('private'),
            Passport::tokenEncryptionKey($this->app->make('encrypter')),
            $responseType ?? new BearerTokenResponse
        );

        $server->setDefaultScope(Passport::$defaultScope);
        $server->revokeRefreshTokens(Passport::$revokeRefreshTokenAfterUse);

        $authCodeGrant = new AuthCodeGrant(
            $this->app->make(AuthCodeRepository::class),
            $this->app->make(RefreshTokenRepository::class),
            $this->app->make(ClaimRepositoryInterface::class),
            $this->app->make(Session::class),
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
        $authCodeGrant->setIssuer(url('/'));

        $server->enableGrantType(
            $authCodeGrant
        );

        $server->enableGrantType(
            new ImplicitGrant(
                $this->app->make(UserRepositoryInterface::class),
                $this->app->make(ClaimRepositoryInterface::class),
                $this->app->make(Session::class),
                new DateInterval('PT10M'),
                new DateInterval('PT10M')
            )
        );

        return $server;
    }

    /**
     * Register the client repository.
     *
     * @return void
     */
    protected function registerClientRepository(): void
    {
        $this->app->singleton(PassportClientRepository::class, function () {
            return new ClientRepository;
        });
    }

    protected function makeGuard(array $config): PassportTokenGuard
    {
        return new TokenGuard(
            $this->app->make(ResourceServer::class),
            new PassportUserProvider(Auth::createUserProvider($config['provider']), $config['provider']),
            $this->app->make(PassportClientRepository::class),
            $this->app->make('encrypter'),
            $this->app->make('request'),
        );
    }

    protected function registerMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
    }

    protected function registerRoutes(): void
    {
        parent::registerRoutes();

        if (Passport::$registersRoutes) {
            Route::group([
                'namespace' => 'Laravel\Passport\Http\Controllers',
            ], function () {
                $this->loadRoutesFrom(__DIR__ . '/../src/routes/web.php');
            });
        }
    }

    public function register(): void
    {
        parent::register();

        $this->registerClientRepository();

        $this->app->when(AuthorizationController::class)
            ->needs(StatefulGuard::class)
            ->give(fn () => Auth::guard(config('passport.guard', null)));
    }
}
