<?php

namespace IdaasPassportTests;

use DateTime;
use DateTimeImmutable;
use Idaas\Passport\KeyRepository;
use Laravel\Passport\Bridge\Scope;
use Mockery as m;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\Entities\ClientEntityInterface;

class UserinfoControllerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $accessTokenRepository = m::mock(\Idaas\Passport\Bridge\AccessTokenRepository::class);
        $accessTokenRepository->shouldReceive('isAccessTokenRevoked')->andReturn(false);
        $accessTokenRepository->shouldReceive('getAccessToken')->andReturn(
            new AccessTokenEntity('123', [], m::mock(ClientEntityInterface::class))
        );

        $this->app->instance(
            \Idaas\Passport\Bridge\AccessTokenRepository::class,
            $accessTokenRepository
        );
    }

    public function testUserinfoBasic()
    {
        $keyRepository = new KeyRepository();

        $config = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($keyRepository->getPrivateKey()->getKeyContents()),
            InMemory::plainText($keyRepository->getPrivateKey()->getKeyContents())
        );

        $token = $config->builder()
            ->permittedFor('client')
            ->identifiedBy('1234')
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt(DateTimeImmutable::createFromMutable(new DateTime("+7 day")))
            ->relatedTo('user-id-1234')
            ->withClaim('scopes', [
                new Scope('openid')
            ])
            ->withClaim('claims', ['claim1'])
            ->getToken($config->signer(), $config->signingKey())
            ->toString();

        $result = $this->get('/oauth/userinfo', [
            'Authorization' => $token
        ]);

        $result->assertStatus(200);

        $result = $this->get('/oauth/connect/register', [
            'Authorization' => $token
        ]);

        $result->assertStatus(200);
    }
}
