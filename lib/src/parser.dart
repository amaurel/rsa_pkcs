part of rsa_pkcs;
// ignore_for_file: public_member_api_docs

/// Parser
class RSAPKCSParser {
  static const String pkcsHeader = '-----';
  static const String pkcs1PublicHeader = '-----BEGIN RSA PUBLIC KEY-----';
  static const String pkcs8PublicHeader = '-----BEGIN PUBLIC KEY-----';
  static const String pkcs1PublicFooter = '-----END RSA PUBLIC KEY-----';
  static const String pkcs8PublicFooter = '-----END PUBLIC KEY-----';

  static const String pkcs1PrivateHeader = '-----BEGIN RSA PRIVATE KEY-----';
  static const String pkcs8PrivateHeader = '-----BEGIN PRIVATE KEY-----';
  static const String pkcs1PrivateFooter = '-----END RSA PRIVATE KEY-----';
  static const String pkcs8PrivateFooter = '-----END PRIVATE KEY-----';

  static const String pkcs8PrivateEncHeader =
      '-----BEGIN ENCRYPTED PRIVATE KEY-----';
  static const String pkcs8PrivateEncFooter =
      '-----END ENCRYPTED PRIVATE KEY-----';

  static const String certHeader = '-----BEGIN CERTIFICATE-----';
  static const String certFooter = '-----END CERTIFICATE-----';

  /// Parse PEM
  RSAKeyPair parsePEM(String pem, {String password}) {
    final List<String> lines = pem
        .split('\n')
        .map((String line) => line.trim())
        .where((String line) => line.isNotEmpty)
        // .skipWhile((String line) => !line.startsWith(pkcsHeader))
        .toList();
    if (lines.isEmpty) {
      _error('format error');
    }
    return RSAKeyPair(_publicKey(lines), _privateKey(lines));
  }

  RSAPrivateKey _privateKey(List<String> lines, {String password}) {
    int header;
    int footer;

    if (lines.contains(pkcs1PrivateHeader)) {
      header = lines.indexOf(pkcs1PrivateHeader);
      footer = lines.indexOf(pkcs1PrivateFooter);
    } else if (lines.contains(pkcs8PrivateHeader)) {
      header = lines.indexOf(pkcs8PrivateHeader);
      footer = lines.indexOf(pkcs8PrivateFooter);
    } else if (lines.contains(pkcs8PrivateEncHeader)) {
      header = lines.indexOf(pkcs8PrivateEncHeader);
      footer = lines.indexOf(pkcs8PrivateEncFooter);
    } else {
      return null;
    }
    if (footer < 0) {
      _error('format error : cannot find footer');
    }
    final String key = lines.sublist(header + 1, footer).join('');
    final Uint8List keyBytes = Uint8List.fromList(base64.decode(key));
    final ASN1Parser p = ASN1Parser(keyBytes);

    final ASN1Sequence seq = p.nextObject();

    if (lines[header] == pkcs1PrivateHeader) {
      return _pkcs1PrivateKey(seq);
    } else if (lines[header] == pkcs8PrivateHeader) {
      return _pkcs8PrivateKey(seq);
    } else {
      return _pkcs8PrivateEncKey(seq, password);
    }
  }

  RSAPublicKey _pkcs8CertificatePrivateKey(ASN1Sequence seq) {
    if (seq.elements.length != 3) _error('Bad certificate format');
    var certificate = seq.elements[0] as ASN1Sequence;

    var subjectPublicKeyInfo = certificate.elements[6] as ASN1Sequence;

    return _pkcs8PublicKey(subjectPublicKeyInfo);
  }

  RSAPrivateKey _pkcs8PrivateEncKey(ASN1Sequence seq, String password) {
    throw UnimplementedError();
    // ASN1OctetString asnkey = (seq.elements[0] as ASN1Sequence).elements[2];
    // var bytes = asnkey.valueBytes();
    // final key = new Uint8List.fromList([
    //   0x00,
    //   0x11,
    //   0x22,
    //   0x33,
    //   0x44,
    //   0x55,
    //   0x66,
    //   0x77,
    //   0x88,
    //   0x99,
    //   0xAA,
    //   0xBB,
    //   0xCC,
    //   0xDD,
    //   0xEE,
    //   0xFF
    // ]);
    // final params = new KeyParameter(key);
    // BlockCipher bc = new BlockCipher("AES");
  }

  RSAPrivateKey _pkcs1PrivateKey(ASN1Sequence seq) {
    final RSAPrivateKey key = RSAPrivateKey();
    final List<ASN1Integer> asn1Ints = seq.elements.cast<ASN1Integer>();
    key.version = asn1Ints[0].intValue;
    key.modulus = asn1Ints[1].valueAsBigInteger;
    key.publicExponent = asn1Ints[2].intValue;
    key.privateExponent = asn1Ints[3].valueAsBigInteger;
    key.prime1 = asn1Ints[4].valueAsBigInteger;
    key.prime2 = asn1Ints[5].valueAsBigInteger;
    key.exponent1 = asn1Ints[6].valueAsBigInteger;
    key.exponent2 = asn1Ints[7].valueAsBigInteger;
    key.coefficient = asn1Ints[8].valueAsBigInteger;
    return key;
  }

  RSAPrivateKey _pkcs8PrivateKey(ASN1Sequence seq) {
    final ASN1OctetString os = seq.elements[2];
    final ASN1Parser p = ASN1Parser(os.valueBytes());
    return _pkcs1PrivateKey(p.nextObject());
  }

  RSAPublicKey _publicKey(List<String> lines) {
    int header;
    int footer;
    if (lines.contains(pkcs1PublicHeader)) {
      header = lines.indexOf(pkcs1PublicHeader);
      footer = lines.indexOf(pkcs1PublicFooter);
    } else if (lines.contains(pkcs8PublicHeader)) {
      header = lines.indexOf(pkcs8PublicHeader);
      footer = lines.indexOf(pkcs8PublicFooter);
    } else if (lines.contains(certHeader)) {
      header = lines.indexOf(certHeader);
      footer = lines.indexOf(certFooter);
    } else {
      return null;
    }
    if (footer < 0) {
      _error('format error : cannot find footer');
    }
    final String key = lines.sublist(header + 1, footer).join('');
    final Uint8List keyBytes = Uint8List.fromList(base64.decode(key));
    final ASN1Parser p = ASN1Parser(keyBytes);

    final ASN1Sequence seq = p.nextObject();

    if (lines[header] == pkcs1PublicHeader) {
      return _pkcs1PublicKey(seq);
    }
    if (lines[header] == pkcs1PublicHeader) {
      return _pkcs1PublicKey(seq);
    } else if (lines[header] == certHeader) {
      return _pkcs8CertificatePrivateKey(seq);
    } else {
      return _pkcs8PublicKey(seq);
    }
  }

  RSAPublicKey _pkcs1PublicKey(ASN1Sequence seq) {
    final RSAPublicKey key = RSAPublicKey();
    final List<ASN1Integer> asn1Ints = seq.elements.cast<ASN1Integer>();
    key.modulus = asn1Ints[0].valueAsBigInteger;
    key.publicExponent = asn1Ints[1].intValue;
    return key;
  }

  RSAPublicKey _pkcs8PublicKey(ASN1Sequence seq) {
    final ASN1BitString os = seq.elements[1]; //ASN1OctetString or ASN1BitString
    final Uint8List bytes = os.valueBytes().sublist(1);
    final ASN1Parser p = ASN1Parser(bytes);
    return _pkcs1PublicKey(p.nextObject());
  }

  void _error(String msg) {
    throw FormatException(msg);
  }
}

/// Key pair
class RSAKeyPair {
  /// Default
  RSAKeyPair(this.public, this.private);

  /// Public key
  RSAPublicKey public;

  /// Private key
  RSAPrivateKey private;
}

/// Public key
class RSAPublicKey {
  /// Modulus
  BigInt modulus;

  /// Exponent
  int publicExponent;
}

/// Private key
class RSAPrivateKey {
  /// Version
  int version;

  /// Modulus
  BigInt modulus;

  /// Exponent - public
  int publicExponent;

  /// Exponent - private
  BigInt privateExponent;

  /// Prime 1
  BigInt prime1;

  /// Prime 2
  BigInt prime2;

  /// Exponent 1
  BigInt exponent1;

  /// Exponent 2
  BigInt exponent2;

  /// Coefficient
  BigInt coefficient;
}

class X509Certificate {
  int version;
  int serial;
}
