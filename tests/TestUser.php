<?php

namespace IdaasPassportTests;

use Illuminate\Foundation\Auth\User;
use Laravel\Passport\HasApiTokens;
use League\OAuth2\Server\Entities\UserEntityInterface;

class TestUser extends User implements UserEntityInterface
{
    use HasApiTokens;

    protected $table = 'users';

    public function findForPassport($identifier)
    {
        return new TestUser([]);
    }

    public function getAuthIdentifier()
    {
        return 'test';
    }

    public function getIdentifier(): string
    {
        return 'test';
    }
}
