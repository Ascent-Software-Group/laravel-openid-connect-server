<?php

namespace IdaasPassportTests;

use Idaas\Passport\PassportServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider as LaravelPassportServiceProvider;
use Mockery as m;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    use RefreshDatabase;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        chmod(__DIR__ . '/files/oauth-private.key', 0600);
        chmod(__DIR__ . '/files/oauth-public.key', 0600);
    }

    protected function setUp(): void
    {
        Passport::loadKeysFrom(__DIR__ . '/files');

        parent::setUp();
    }

    protected function tearDown(): void
    {
        m::close();

        parent::tearDown();
    }

    protected function getPackageProviders($app): array
    {
        return [LaravelPassportServiceProvider::class, PassportServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('a', 32)));
        $app['config']->set('auth.providers.users.model', TestUser::class);
        $app['config']->set('auth.guards.api', ['driver' => 'passport', 'provider' => 'users']);
    }
}
