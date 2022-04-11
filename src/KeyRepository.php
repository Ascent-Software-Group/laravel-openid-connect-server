<?php

namespace Idaas\Passport;

use Idaas\OpenID\CryptKey;
use Idaas\Passport\Model\Client;
use Laravel\Passport\Passport;

class KeyRepository
{
    public function getPrivateKey()
    {
        return new CryptKey(config('passport.private_key'));
    }

    public function getPublicKey()
    {
        return new CryptKey(
            config('passport.public_key')
        );
    }

    public function getPublicKeyForClient(Client $client, $kid = null)
    {
        return new CryptKey(config('passport.public_key'));
    }

    public function getAllPublicKeys()
    {
        return [$this->getPublicKey()];
    }

    public function getPrivateKeyByKid($kid)
    {
        return $this->getPrivateKey();
    }

    public static function generateNew()
    {
        $dn = array(
            "countryName" => "US",
            "stateOrProvinceName" => "Utah",
            "localityName" => "Alpine",
            "organizationName" => "Ascent Software Group",
            "organizationalUnitName" => "Jaro",
            "commonName" => "a11n",
            "emailAddress" => "help@jarodesk.com"
        );

        // Generate a new private (and public) key pair
        $privkey = openssl_pkey_new(array(
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ));

        // Generate a certificate signing request
        $csr = openssl_csr_new($dn, $privkey, array('digest_alg' => 'sha256'));

        // Generate a self-signed cert, valid for 365 days
        $x509 = openssl_csr_sign($csr, null, $privkey, 365, array('digest_alg' => 'sha256'));

        openssl_x509_export($x509, $certout);
        openssl_pkey_export($privkey, $pkeyout);

        $publicKey = openssl_pkey_get_details(openssl_pkey_get_public($x509));

        return ['x509' => $certout, 'public_key' => $publicKey['key'], 'private_key' => $pkeyout];
    }
}
