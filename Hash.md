# How to hash data with salt in C# or VB.NET

## Description
These code samples demonstrate how to hash data and verify hashes. It supports several hashing algorithms. To help reduce the risk of dictionary attacks, the code prepends random bytes (so-called salt) to the original plain text before generating hashes and appends them to the generated ciphertext (original salt value will be needed for hash verification). The resulting ciphertext is base64-encoded. IMPORTANT: DATA HASHES CANNOT BE DECRYPTED BACK TO PLAIN TEXT.

## Disclaimer
These code samples are offered for demonstration purpose only. In a real-life application you may need to modify the code to make it more efficient. For example, instead of appending salt values to generated hashes, you may want to store them separately. Another performance improvement can be achieved by not converting results into base64-encoded strings, but manipulating them in a byte array format. Use these code samples at your own risk.

## C# code sample
``` CSharp
///////////////////////////////////////////////////////////////////////////////
// SAMPLE: Hashing data with salt using MD5 and several SHA algorithms.
//
// To run this sample, create a new Visual C# project using the Console
// Application template and replace the contents of the Class1.cs file with
// the code below.
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
// EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
// 
// Copyright (C) 2002 Obviex(TM). All rights reserved.
// 
using System;
using System.Text;
using System.Security.Cryptography;

/// <summary>
/// This class generates and compares hashes using MD5, SHA1, SHA256, SHA384, 
/// and SHA512 hashing algorithms. Before computing a hash, it appends a
/// randomly generated salt to the plain text, and stores this salt appended
/// to the result. To verify another plain text value against the given hash,
/// this class will retrieve the salt value from the hash string and use it
/// when computing a new hash of the plain text. Appending a salt value to
/// the hash may not be the most efficient approach, so when using hashes in
/// a real-life application, you may choose to store them separately. You may
/// also opt to keep results as byte arrays instead of converting them into
/// base64-encoded strings.
/// </summary>
public class SimpleHash
{
    /// <summary>
    /// Generates a hash for the given plain text value and returns a
    /// base64-encoded result. Before the hash is computed, a random salt
    /// is generated and appended to the plain text. This salt is stored at
    /// the end of the hash value, so it can be used later for hash
    /// verification.
    /// </summary>
    /// <param name="plainText">
    /// Plaintext value to be hashed. The function does not check whether
    /// this parameter is null.
    /// </param>
    /// <param name="hashAlgorithm">
    /// Name of the hash algorithm. Allowed values are: "MD5", "SHA1",
    /// "SHA256", "SHA384", and "SHA512" (if any other value is specified
    /// MD5 hashing algorithm will be used). This value is case-insensitive.
    /// </param>
    /// <param name="saltBytes">
    /// Salt bytes. This parameter can be null, in which case a random salt
    /// value will be generated.
    /// </param>
    /// <returns>
    /// Hash value formatted as a base64-encoded string.
    /// </returns>
    public static string ComputeHash(string   plainText,
                                     string   hashAlgorithm,
                                     byte[]   saltBytes)
    {
        // If salt is not specified, generate it on the fly.
        if (saltBytes == null)
        {
            // Define min and max salt sizes.
            int minSaltSize = 4;
            int maxSaltSize = 8;

            // Generate a random number for the size of the salt.
            Random  random = new Random();
            int saltSize = random.Next(minSaltSize, maxSaltSize);

            // Allocate a byte array, which will hold the salt.
            saltBytes = new byte[saltSize];

            // Initialize a random number generator.
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

            // Fill the salt with cryptographically strong byte values.
            rng.GetNonZeroBytes(saltBytes); 
        }
        
        // Convert plain text into a byte array.
        byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
        
        // Allocate array, which will hold plain text and salt.
        byte[] plainTextWithSaltBytes = 
                new byte[plainTextBytes.Length + saltBytes.Length];

        // Copy plain text bytes into resulting array.
        for (int i=0; i < plainTextBytes.Length; i++)
            plainTextWithSaltBytes[i] = plainTextBytes[i];
        
        // Append salt bytes to the resulting array.
        for (int i=0; i < saltBytes.Length; i++)
            plainTextWithSaltBytes[plainTextBytes.Length + i] = saltBytes[i];

        // Because we support multiple hashing algorithms, we must define
        // hash object as a common (abstract) base class. We will specify the
        // actual hashing algorithm class later during object creation.
        HashAlgorithm hash;
        
        // Make sure hashing algorithm name is specified.
        if (hashAlgorithm == null)
            hashAlgorithm = "";
        
        // Initialize appropriate hashing algorithm class.
        switch (hashAlgorithm.ToUpper())
        {
            case "SHA1":
                hash = new SHA1Managed();
                break;

            case "SHA256":
                hash = new SHA256Managed();
                break;

            case "SHA384":
                hash = new SHA384Managed();
                break;

            case "SHA512":
                hash = new SHA512Managed();
                break;

            default:
                hash = new MD5CryptoServiceProvider();
                break;
        }
        
        // Compute hash value of our plain text with appended salt.
        byte[] hashBytes = hash.ComputeHash(plainTextWithSaltBytes);
        
        // Create array which will hold hash and original salt bytes.
        byte[] hashWithSaltBytes = new byte[hashBytes.Length + 
                                            saltBytes.Length];
        
        // Copy hash bytes into resulting array.
        for (int i=0; i < hashBytes.Length; i++)
            hashWithSaltBytes[i] = hashBytes[i];
            
        // Append salt bytes to the result.
        for (int i=0; i < saltBytes.Length; i++)
            hashWithSaltBytes[hashBytes.Length + i] = saltBytes[i];
            
        // Convert result into a base64-encoded string.
        string hashValue = Convert.ToBase64String(hashWithSaltBytes);
        
        // Return the result.
        return hashValue;
    }

    /// <summary>
    /// Compares a hash of the specified plain text value to a given hash
    /// value. Plain text is hashed with the same salt value as the original
    /// hash.
    /// </summary>
    /// <param name="plainText">
    /// Plain text to be verified against the specified hash. The function
    /// does not check whether this parameter is null.
    /// </param>
    /// <param name="hashAlgorithm">
    /// Name of the hash algorithm. Allowed values are: "MD5", "SHA1", 
    /// "SHA256", "SHA384", and "SHA512" (if any other value is specified,
    /// MD5 hashing algorithm will be used). This value is case-insensitive.
    /// </param>
    /// <param name="hashValue">
    /// Base64-encoded hash value produced by ComputeHash function. This value
    /// includes the original salt appended to it.
    /// </param>
    /// <returns>
    /// If computed hash mathes the specified hash the function the return
    /// value is true; otherwise, the function returns false.
    /// </returns>
    public static bool VerifyHash(string   plainText,
                                  string   hashAlgorithm,
                                  string   hashValue)
    {
        // Convert base64-encoded hash value into a byte array.
        byte[] hashWithSaltBytes = Convert.FromBase64String(hashValue);
        
        // We must know size of hash (without salt).
        int hashSizeInBits, hashSizeInBytes;
        
        // Make sure that hashing algorithm name is specified.
        if (hashAlgorithm == null)
            hashAlgorithm = "";
        
        // Size of hash is based on the specified algorithm.
        switch (hashAlgorithm.ToUpper())
        {
            case "SHA1":
                hashSizeInBits = 160;
                break;

            case "SHA256":
                hashSizeInBits = 256;
                break;

            case "SHA384":
                hashSizeInBits = 384;
                break;

            case "SHA512":
                hashSizeInBits = 512;
                break;

            default: // Must be MD5
                hashSizeInBits = 128;
                break;
        }

        // Convert size of hash from bits to bytes.
        hashSizeInBytes = hashSizeInBits / 8;

        // Make sure that the specified hash value is long enough.
        if (hashWithSaltBytes.Length < hashSizeInBytes)
            return false;

        // Allocate array to hold original salt bytes retrieved from hash.
        byte[] saltBytes = new byte[hashWithSaltBytes.Length - 
                                    hashSizeInBytes];

        // Copy salt from the end of the hash to the new array.
        for (int i=0; i < saltBytes.Length; i++)
            saltBytes[i] = hashWithSaltBytes[hashSizeInBytes + i];

        // Compute a new hash string.
        string expectedHashString = 
                    ComputeHash(plainText, hashAlgorithm, saltBytes);

        // If the computed hash matches the specified hash,
        // the plain text value must be correct.
        return (hashValue == expectedHashString);
    }
}

/// <summary>
/// Illustrates the use of the SimpleHash class.
/// </summary>
public class SimpleHashTest
{
    /// <summary>
    /// The main entry point for the application.
    /// </summary>
    [STAThread]
    static void Main(string[] args)
    {
        string password      = "myP@5sw0rd";  // original password
        string wrongPassword = "password";    // wrong password
 
        string passwordHashMD5 = 
               SimpleHash.ComputeHash(password, "MD5", null);
        string passwordHashSha1 = 
               SimpleHash.ComputeHash(password, "SHA1", null);
        string passwordHashSha256 = 
               SimpleHash.ComputeHash(password, "SHA256", null);
        string passwordHashSha384 = 
               SimpleHash.ComputeHash(password, "SHA384", null);
        string passwordHashSha512 = 
               SimpleHash.ComputeHash(password, "SHA512", null);

        Console.WriteLine("COMPUTING HASH VALUES\r\n");
        Console.WriteLine("MD5   : {0}", passwordHashMD5);
        Console.WriteLine("SHA1  : {0}", passwordHashSha1);
        Console.WriteLine("SHA256: {0}", passwordHashSha256);
        Console.WriteLine("SHA384: {0}", passwordHashSha384);
        Console.WriteLine("SHA512: {0}", passwordHashSha512);
        Console.WriteLine("");

        Console.WriteLine("COMPARING PASSWORD HASHES\r\n");
        Console.WriteLine("MD5    (good): {0}",
                            SimpleHash.VerifyHash(
                            password, "MD5", 
                            passwordHashMD5).ToString());
        Console.WriteLine("MD5    (bad) : {0}",
                            SimpleHash.VerifyHash(
                            wrongPassword, "MD5", 
                            passwordHashMD5).ToString());
        Console.WriteLine("SHA1   (good): {0}",
                            SimpleHash.VerifyHash(
                            password, "SHA1", 
                            passwordHashSha1).ToString());
        Console.WriteLine("SHA1   (bad) : {0}",
                            SimpleHash.VerifyHash(
                            wrongPassword, "SHA1", 
                            passwordHashSha1).ToString());
        Console.WriteLine("SHA256 (good): {0}",
                            SimpleHash.VerifyHash(
                            password, "SHA256", 
                            passwordHashSha256).ToString());
        Console.WriteLine("SHA256 (bad) : {0}",
                            SimpleHash.VerifyHash(
                            wrongPassword, "SHA256", 
                            passwordHashSha256).ToString());
        Console.WriteLine("SHA384 (good): {0}",
                            SimpleHash.VerifyHash(
                            password, "SHA384", 
                            passwordHashSha384).ToString());
        Console.WriteLine("SHA384 (bad) : {0}", 
                            SimpleHash.VerifyHash(
                            wrongPassword, "SHA384", 
                            passwordHashSha384).ToString());
        Console.WriteLine("SHA512 (good): {0}",
                            SimpleHash.VerifyHash(
                            password, "SHA512", 
                            passwordHashSha512).ToString());
        Console.WriteLine("SHA512 (bad) : {0}",
                            SimpleHash.VerifyHash(
                            wrongPassword, "SHA512", 
                            passwordHashSha512).ToString());
    }
}
//
// END OF FILE
///////////////////////////////////////////////////////////////////////////////
```

## VB.NET code sample
``` VB
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' SAMPLE: Hashing data with salt using MD5 and several SHA algorithms.
'
' To run this sample, create a new Visual Basic.NET project using the Console
' Application template and replace the contents of the Module1.vb file with
' the code below.
'
' THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
' EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
' WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
' 
' Copyright (C) 2002 Obviex(TM). All rights reserved.
'
Imports System
Imports System.Text
Imports System.Security.Cryptography

Module Module1

' <summary>
' This class generates and compares hashes using MD5, SHA1, SHA256, SHA384, 
' and SHA512 hashing algorithms. Before computing a hash, it appends a
' randomly generated salt to the plain text, and stores this salt appended
' to the result. To verify another plain text value against the given hash,
' this class will retrieve the salt value from the hash string and use it
' when computing a new hash of the plain text. Appending a salt value to
' the hash may not be the most efficient approach, so when using hashes in
' a real-life application, you may choose to store them separately. You may
' also opt to keep results as byte arrays instead of converting them into
' base64-encoded strings.
' </summary>
Public Class SimpleHash

    ' <summary>
    ' Generates a hash for the given plain text value and returns a
    ' base64-encoded result. Before the hash is computed, a random salt
    ' is generated and appended to the plain text. This salt is stored at
    ' the end of the hash value, so it can be used later for hash
    ' verification.
    ' </summary>
    ' <param name="plainText">
    ' Plaintext value to be hashed. The function does not check whether
    ' this parameter is null.
    ' </param>
    ' < name="hashAlgorithm">
    ' Name of the hash algorithm. Allowed values are: "MD5", "SHA1",
    ' "SHA256", "SHA384", and "SHA512" (if any other value is specified
    ' MD5 hashing algorithm will be used). This value is case-insensitive.
    ' </param>
    ' < name="saltBytes">
    ' Salt bytes. This parameter can be null, in which case a random salt
    ' value will be generated.
    ' </param>
    ' <returns>
    ' Hash value formatted as a base64-encoded string.
    ' </returns>
    Public Shared Function ComputeHash(ByVal plainText     As String, _
                                       ByVal hashAlgorithm As String, _
                                       ByVal saltBytes()   As Byte) _
                           As String

        ' If salt is not specified, generate it on the fly.
        If (saltBytes Is Nothing) Then

            ' Define min and max salt sizes.
            Dim minSaltSize As Integer
            Dim maxSaltSize As Integer

            minSaltSize = 4
            maxSaltSize = 8

            ' Generate a random number for the size of the salt.
            Dim random As Random
            random = New Random()

            Dim saltSize As Integer
            saltSize = random.Next(minSaltSize, maxSaltSize)

            ' Allocate a byte array, which will hold the salt.
            saltBytes = New Byte(saltSize - 1){}

            ' Initialize a random number generator.
            Dim rng As RNGCryptoServiceProvider 
            rng = New RNGCryptoServiceProvider()

            ' Fill the salt with cryptographically strong byte values.
            rng.GetNonZeroBytes(saltBytes) 
        End If

        ' Convert plain text into a byte array.
        Dim plainTextBytes As Byte()
        plainTextBytes = Encoding.UTF8.GetBytes(plainText)

        ' Allocate array, which will hold plain text and salt.
        Dim plainTextWithSaltBytes() As Byte = _
            New Byte(plainTextBytes.Length + saltBytes.Length - 1){}

        ' Copy plain text bytes into resulting array.
        Dim I As Integer
        For I = 0 To plainTextBytes.Length - 1
            plainTextWithSaltBytes(I) = plainTextBytes(I)
        Next I

        ' Append salt bytes to the resulting array.
        For I = 0 To saltBytes.Length - 1
            plainTextWithSaltBytes(plainTextBytes.Length + I) = saltBytes(I)
        Next I

        ' Because we support multiple hashing algorithms, we must define
        ' hash object as a common (abstract) base class. We will specify the
        ' actual hashing algorithm class later during object creation.
        Dim hash As HashAlgorithm

        ' Make sure hashing algorithm name is specified.
        If (hashAlgorithm Is Nothing) Then
            hashAlgorithm = ""
        End If

        ' Initialize appropriate hashing algorithm class.
        Select hashAlgorithm.ToUpper()

            Case "SHA1"
                hash = New SHA1Managed()

            Case "SHA256"
                hash = New SHA256Managed()

            Case "SHA384"
                hash = New SHA384Managed()

            Case "SHA512"
                hash = New SHA512Managed()

            Case Else
                hash = New MD5CryptoServiceProvider()

        End Select

        ' Compute hash value of our plain text with appended salt.
        Dim hashBytes As Byte()
        hashBytes = hash.ComputeHash(plainTextWithSaltBytes)

        ' Create array which will hold hash and original salt bytes.
        Dim hashWithSaltBytes() As Byte = _
                                   New Byte(hashBytes.Length + _
                                            saltBytes.Length - 1) {}

        ' Copy hash bytes into resulting array.
        For I = 0 To hashBytes.Length - 1
            hashWithSaltBytes(I) = hashBytes(I)
        Next I

        ' Append salt bytes to the result.
        For I = 0 To saltBytes.Length - 1
            hashWithSaltBytes(hashBytes.Length + I) = saltBytes(I)
        Next I

        ' Convert result into a base64-encoded string.
        Dim hashValue As String
        hashValue = Convert.ToBase64String(hashWithSaltBytes)

        ' Return the result.
        ComputeHash = hashValue
    End Function

    ' <summary>
    ' Compares a hash of the specified plain text value to a given hash
    ' value. Plain text is hashed with the same salt value as the original
    ' hash.
    ' </summary>
    ' <param name="plainText">
    ' Plain text to be verified against the specified hash. The function
    ' does not check whether this parameter is null.
    ' </param>
    ' < name="hashAlgorithm">
    ' Name of the hash algorithm. Allowed values are: "MD5", "SHA1",
    ' "SHA256", "SHA384", and "SHA512" (if any other value is specified
    ' MD5 hashing algorithm will be used). This value is case-insensitive.
    ' </param>
    ' < name="hashValue">
    ' Base64-encoded hash value produced by ComputeHash function. This value
    ' includes the original salt appended to it.
    ' </param>
    ' <returns>
    ' If computed hash mathes the specified hash the function the return
    ' value is true; otherwise, the function returns false.
    ' </returns>
    Public Shared Function VerifyHash(ByVal plainText     As String, _
                                      ByVal hashAlgorithm As String, _
                                      ByVal hashValue    As String) _
                           As Boolean
    
        ' Convert base64-encoded hash value into a byte array.
        Dim hashWithSaltBytes As Byte()
        hashWithSaltBytes = Convert.FromBase64String(hashValue)

        ' We must know size of hash (without salt).
        Dim hashSizeInBits  As Integer
        Dim hashSizeInBytes As Integer

        ' Make sure that hashing algorithm name is specified.
        If (hashAlgorithm Is Nothing) Then
            hashAlgorithm = ""
        End If

        ' Size of hash is based on the specified algorithm.
        Select hashAlgorithm.ToUpper()

            Case "SHA1"
                hashSizeInBits = 160

            Case "SHA256"
                hashSizeInBits = 256

            Case "SHA384"
                hashSizeInBits = 384

            Case "SHA512"
                hashSizeInBits = 512

            Case Else ' Must be MD5
                hashSizeInBits = 128

        End Select

        ' Convert size of hash from bits to bytes.
        hashSizeInBytes = hashSizeInBits / 8

        ' Make sure that the specified hash value is long enough.
        If (hashWithSaltBytes.Length < hashSizeInBytes) Then
            VerifyHash = False
        End If

        ' Allocate array to hold original salt bytes retrieved from hash.
        Dim saltBytes() As Byte = New Byte(hashWithSaltBytes.Length - _
                                           hashSizeInBytes - 1) {}

        ' Copy salt from the end of the hash to the new array.
        Dim I As Integer
        For I = 0 To saltBytes.Length - 1
            saltBytes(I) = hashWithSaltBytes(hashSizeInBytes + I)
        Next I

        ' Compute a new hash string.
        Dim expectedHashString As String 
        expectedHashString = ComputeHash(plainText, hashAlgorithm, saltBytes)

        ' If the computed hash matches the specified hash,
        ' the plain text value must be correct.
        VerifyHash = (hashValue = expectedHashString)
    End Function
End Class

' <summary>
' The main entry point for the application.
' </summary>
Sub Main()

        Dim password      As String    ' original password
        Dim wrongPassword As String    ' wrong password
        
        password      = "myP@5sw0rd"
        wrongPassword = "password"

        Dim passwordHashMD5    As String
        Dim passwordHashSha1   As String
        Dim passwordHashSha256 As String
        Dim passwordHashSha384 As String
        Dim passwordHashSha512 As String

        passwordHashMD5 = _
               SimpleHash.ComputeHash(password, "MD5", Nothing)
        passwordHashSha1 = _
               SimpleHash.ComputeHash(password, "SHA1", Nothing)
        passwordHashSha256 = _
               SimpleHash.ComputeHash(password, "SHA256", Nothing)
        passwordHashSha384 = _
               SimpleHash.ComputeHash(password, "SHA384", Nothing)
        passwordHashSha512 = _
               SimpleHash.ComputeHash(password, "SHA512", Nothing)

        Console.WriteLine("COMPUTING HASH VALUES")
        Console.WriteLine("")
        Console.WriteLine("MD5   : {0}", passwordHashMD5)
        Console.WriteLine("SHA1  : {0}", passwordHashSha1)
        Console.WriteLine("SHA256: {0}", passwordHashSha256)
        Console.WriteLine("SHA384: {0}", passwordHashSha384)
        Console.WriteLine("SHA512: {0}", passwordHashSha512)
        Console.WriteLine("")

        Console.WriteLine("COMPARING PASSWORD HASHES")
        Console.WriteLine("")
        Console.WriteLine("MD5    (good): {0}", _
                            SimpleHash.VerifyHash( _
                            password, "MD5", _
                            passwordHashMD5).ToString())
        Console.WriteLine("MD5    (bad) : {0}", _
                            SimpleHash.VerifyHash( _
                            wrongPassword, "MD5", _
                            passwordHashMD5).ToString())
        Console.WriteLine("SHA1   (good): {0}", _
                            SimpleHash.VerifyHash( _
                            password, "SHA1", _
                            passwordHashSha1).ToString())
        Console.WriteLine("SHA1   (bad) : {0}", _
                            SimpleHash.VerifyHash( _
                            wrongPassword, "SHA1", _
                            passwordHashSha1).ToString())
        Console.WriteLine("SHA256 (good): {0}", _
                            SimpleHash.VerifyHash( _
                            password, "SHA256", _
                            passwordHashSha256).ToString())
        Console.WriteLine("SHA256 (bad) : {0}", _
                            SimpleHash.VerifyHash( _
                            wrongPassword, "SHA256", _ 
                            passwordHashSha256).ToString())
        Console.WriteLine("SHA384 (good): {0}", _
                            SimpleHash.VerifyHash( _
                            password, "SHA384", _
                            passwordHashSha384).ToString())
        Console.WriteLine("SHA384 (bad) : {0}", _
                            SimpleHash.VerifyHash( _
                            wrongPassword, "SHA384", _ 
                            passwordHashSha384).ToString())
        Console.WriteLine("SHA512 (good): {0}", _
                            SimpleHash.VerifyHash( _
                            password, "SHA512", _
                            passwordHashSha512).ToString())
        Console.WriteLine("SHA512 (bad) : {0}", _
                            SimpleHash.VerifyHash( _
                            wrongPassword, "SHA512", _ 
                            passwordHashSha512).ToString())
End Sub

End Module
'
' END OF FILE
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
```

## Program output
```
COMPUTING HASH VALUES

MD5   : SC4LSYSAkKILp2rPW1ZVpOP1WK7g
SHA1  : E0CfoAleTy9lDL8PmqLlY76jg3k/as3G5DPe
SHA256: p4OqMcDW33DzkGR7+UskcFv75yq/Jb7K49mRwRYHLdw0+HTwq3sS
SHA384: Tq6F1p1Hhan+tGPLOS+T6ltPh7wvTtPqgvgd4BKCTPEGnXCOEQpcrm0IELEjnobkWKY9...
SHA512: UjtzgRAx4BWpMKYb1Qnrhn3Nlj84MrKNX1zJbNW33saM9IEtRmpzn4Ny6Y5oITg3TkSZ...

COMPARING PASSWORD HASHES

MD5    (good): True
MD5    (bad) : False
SHA1   (good): True
SHA1   (bad) : False
SHA256 (good): True
SHA256 (bad) : False
SHA384 (good): True
SHA384 (bad) : False
SHA512 (good): True
SHA512 (bad) : False
```
