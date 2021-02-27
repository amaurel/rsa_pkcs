library rsa_pkcs_test;

import 'dart:io';
import 'package:test/test.dart';
import 'package:rsa_pkcs/rsa_pkcs.dart';

/// Test suite
void main() {
  test('X509 certificate', () {
    final certificateFile = File('test/resource/certificate.pem');
    final pem = certificateFile.readAsStringSync();

    final parser = RSAPKCSParser();
    final pair = parser.parsePEM(pem);

    expect(pair.private, isNull);
    expect(pair.public, isNotNull);

    expect(
        pair.public!.modulus,
        BigInt.parse(
          '28033090497217768360343969660651078939521584065407386701840944857554190333345377486890608592313957403519912593868573272324833566960046565212209064828701606844042844758296252915683436083950709369588282830401703789082050482708460081183032757865928569658700963214439372520258229921591300947157909982421739994731742762665888890674063869593136209633509251161824923657193583205462354862058115540928040675840828039354822562384195703281964881672495986693976525885611588824710685812476559097665742184509878129643078068928823514354625680850083823859349966847983641526471178472606740080720731992805405488827115995037727686469357',
        ));
    expect(pair.public!.publicExponent, equals(65537));
  });

  test('rsa private key PKCS#1', () {
    //openssl genrsa -out rsa_private_key.pem
    //
    final rsaPrivateKeyFile = File('test/resource/rsa_private_key.pem');
    final pem = rsaPrivateKeyFile.readAsStringSync();
    final parser = RSAPKCSParser();
    final pair = parser.parsePEM(pem);
    final privateKey = pair.private;

    expect(pair.public, equals(null));
    expect(privateKey!, isNotNull);
    expect(privateKey.version, equals(0));
    final BigInt expectedModulus = BigInt.parse(
      '00d83c3cacb3b767a1020f947ca2012010ba494d86bda1efd437357b91d5c1e61b12384cd3c01f628312a5ef15cf003f62c4f6b835bbb3ea99409f87e583fa6991',
      radix: 16,
    );
    expect(privateKey.modulus, expectedModulus);
    expect(privateKey.publicExponent, equals(65537));

    final BigInt expectedPrivateComponent = BigInt.parse(
        '00a0c22fcda992b9cd5eeddc53c85193d83bd6917791f6198a293d6ecfde1e5885fbc0a766aaca385dd8b3b16a58201baec3900b5c1636321a0167e956d5fbe001',
        radix: 16);
    expect(privateKey.privateExponent, expectedPrivateComponent);
    expect(
        privateKey.prime1,
        BigInt.parse(
            '00f3103a1bb14f88f096983ecd86cb51f9e0e9325030039be4fbb4176de1b73f91',
            radix: 16));
    expect(
        privateKey.prime2,
        BigInt.parse(
            '00e3be793b593e4ed5bce5db1ff563468eeb5cc715b12badf223d1970cd88f8a01',
            radix: 16));
    expect(
        privateKey.exponent1,
        BigInt.parse(
            '7e4e8863ab98310914b8b8aa04c9d3278e809fec9b86c49411585c74753ecc81',
            radix: 16));
    expect(
        privateKey.exponent2,
        BigInt.parse(
            '687f8272f7ecfe11569e855ff1a17ec39f3d2fe0452e0c9f794df7281eca2601',
            radix: 16));
    expect(
        privateKey.coefficient,
        BigInt.parse(
            '0092e895c1a9b7b705fb694bba2d52cb9901d4628db794eb43861b086c557d2913',
            radix: 16));
  });

  test('rsa public key PKCS#8', () {
    //openssl genrsa -out rsa_private_key.pem
    //openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
    final File rsaPrivateKeyFile = File('test/resource/rsa_public_key.pem');
    final String pem = rsaPrivateKeyFile.readAsStringSync();
    final RSAPKCSParser parser = RSAPKCSParser();
    final RSAKeyPair pair = parser.parsePEM(pem);
    final RSAPrivateKey? privateKey = pair.private;
    final RSAPublicKey publicKey = pair.public!;

    expect(privateKey, equals(null));
    expect(publicKey != null, equals(true));

    expect(
        publicKey.modulus,
        BigInt.parse(
            '00d83c3cacb3b767a1020f947ca2012010ba494d86bda1efd437357b91d5c1e61b12384cd3c01f628312a5ef15cf003f62c4f6b835bbb3ea99409f87e583fa6991',
            radix: 16));
    expect(publicKey.publicExponent, equals(65537));
  });
//  test('rsa private key PKCS#8', () {
//    //openssl genrsa -out rsa_private_key.pem
//    //openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
//    final File rsaPrivateKeyFile =
//        File('test/resource/rsa_pkcs8_private_key.pem');
//    final String pem = rsaPrivateKeyFile.readAsStringSync();
//    final RSAPKCSParser parser = RSAPKCSParser();
//    final RSAKeyPair pair = parser.parsePEM(pem);
//    final RSAPrivateKey privateKey = pair.private;
//    final RSAPublicKey publicKey = pair.public;
//
//    expect(privateKey != null, equals(true));
//    expect(publicKey, equals(null));
//
//    expect(
//        privateKey.modulus,
//        BigInt.parse(
//            '00d83c3cacb3b767a1020f947ca2012010ba494d86bda1efd437357b91d5c1e61b12384cd3c01f628312a5ef15cf003f62c4f6b835bbb3ea99409f87e583fa6991',
//            radix: 16));
//    expect(
//        privateKey.privateExponent,
//        BigInt.parse(
//            '00a0c22fcda992b9cd5eeddc53c85193d83bd6917791f6198a293d6ecfde1e5885fbc0a766aaca385dd8b3b16a58201baec3900b5c1636321a0167e956d5fbe001',
//            radix: 16));
//  });
}
