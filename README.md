# Samples
The following code samples illustrate how to use cryptography in C# and VisualBasic.NET for such common tasks as data encryption, hashing, and random password generation.

## [How to encrypt and decrypt data using a symmetric key](Encryption.md)
Illustrates how to generate a persistent (i.e. non-random) symmetric key and use this key to encrypt and decrypt data. This sample is intended to help novice users get a grasp on encryption and decryption.

## [How to encrypt and decrypt data with salt](EncryptionWithSalt.md)
Explains how to use random salt values when encrypting the same plain text value with the same symmetric key to generate different cipher text. This approach eliminates the need to use different initialization vectors or keys for the purpose of avoiding dictionary attacks.

## [How to encrypt and decrypt data using DPAPI](Dpapi.md)
Demonstrates how to encrypt and decrypt data using Windows Data Protection API ([DPAPI](https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10))).

## [How to hash data with salt](Hash.md)
Illustrates how to hash a text string with a random salt value using various hashing algorithms and verify a hash against a plain text value.

## [How to generate a random password](Password.md)
Shows how to generate a random password, which consists of a combination of 7-bit ASCII alpha-numeric characters and special symbols, but does not contain ambiguous characters (such as [1,I,l]).
