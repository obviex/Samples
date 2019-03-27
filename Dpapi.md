# How to encrypt and decrypt data using DPAPI in C# or VB.NET

## Description
These code samples demonstrate how to call Data Protection API (DPAPI) functions [CryptProtectData](https://docs.microsoft.com/en-us/windows/desktop/api/dpapi/nf-dpapi-cryptprotectdata) and [CryptUnprotectData](https://docs.microsoft.com/en-us/windows/desktop/api/dpapi/nf-dpapi-cryptunprotectdata) to encrypt and decrypt data in managed code.

### Background
DPAPI functions encrypt and decrypt data using the [Triple-DES](https://en.wikipedia.org/wiki/Triple_DES) algorithm. In addition to encryption and decryption, DPAPI handles key generation and protection. DPAPI can generate encryption keys that are unique either for a Windows® user making the call or the computer on which the program making the call runs. You cannot combine a user-specific key with machine-specific key in a single DPAPI call.

### DPAPI with user-specific keys
When making DPAPI calls with user-specific keys, encryption and decryption must be performed by the same Windows® user, i.e. the Windows® account under which the application runs. Applications calling DPAPI functions with user-specific keys must run with loaded user profiles; they cannot use the profiles of the built-in system accounts, such as `LocalSystem`, `ASPNET`, `IUSR_MachineName`, etc. The user profile must be created on the system where DPAPI calls are made, which normally requires the user to log on to the system interactively at least once. IMPORTANT: Normally, ASP.NET applications and other programs running under the built-in system accounts, such as Windows® services running as `LocalSystem`, cannot use DPAPI with user-specific keys.

### DPAPI with machine-specific keys
When making DPAPI calls with machine-specific keys, encryption and decryption can be performed by any user or application as long as both operations are executed on the same computer. Any application - including ASP.NET applications - can use DPAPI with machine-specific keys. It is worth noting that this option is not secure because it allows a malicious application installed on a system to decrypt any data encrypted by other applications on the same system using DPAPI with machine-specific keys.

### Secondary entropy
When an application calls the DPAPI encryption routine, it can specify an optional secondary entropy ("secret" bytes) that will have to be provided by an application attempting to decrypt data. The secondary entropy can be used with either user- or machine-specific keys. It must be protected.

### Data description
When an application calls the DPAPI encryption routine, it can specify an optional data description. The data description will be returned by the DPAPI decryption routine.

## Disclaimer
These code samples are provided for demonstration purpose only. Use at your own risk.

## C# code sample
``` CSharp
///////////////////////////////////////////////////////////////////////////////
// SAMPLE: Encryption and decryption using DPAPI functions.
//
// To run this sample, create a new Visual C# project using the Console
// Application template and replace the contents of the Class1.cs file
// with the code below.
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
// KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
// PURPOSE.
//
// Copyright (C) 2003 Obviex(TM). All rights reserved.
//
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;

/// <summary>
/// Encrypts and decrypts data using DPAPI functions.
/// </summary>
public class DPAPI
{
    // Wrapper for DPAPI CryptProtectData function.
    [DllImport( "crypt32.dll",
                SetLastError=true,
                CharSet=System.Runtime.InteropServices.CharSet.Auto)]
    private static extern
        bool CryptProtectData(  ref DATA_BLOB     pPlainText,
                                    string        szDescription,
                                ref DATA_BLOB     pEntropy,
                                    IntPtr        pReserved,
                                ref CRYPTPROTECT_PROMPTSTRUCT pPrompt,
                                    int           dwFlags,
                                ref DATA_BLOB     pCipherText);

    // Wrapper for DPAPI CryptUnprotectData function.
    [DllImport( "crypt32.dll",
                SetLastError=true,
                CharSet=System.Runtime.InteropServices.CharSet.Auto)]
    private static extern
        bool CryptUnprotectData(ref DATA_BLOB       pCipherText,
                                ref string          pszDescription,
                                ref DATA_BLOB       pEntropy,
                                    IntPtr          pReserved,
                                ref CRYPTPROTECT_PROMPTSTRUCT pPrompt,
                                    int             dwFlags,
                                ref DATA_BLOB       pPlainText);

    // BLOB structure used to pass data to DPAPI functions.
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    internal struct DATA_BLOB
    {
        public int     cbData;
        public IntPtr  pbData;
    }

    // Prompt structure to be used for required parameters.
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    internal struct CRYPTPROTECT_PROMPTSTRUCT
    {
        public int      cbSize;
        public int      dwPromptFlags;
        public IntPtr   hwndApp;
        public string   szPrompt;
    }

    // Wrapper for the NULL handle or pointer.
    static private IntPtr NullPtr = ((IntPtr)((int)(0)));

    // DPAPI key initialization flags.
    private const int CRYPTPROTECT_UI_FORBIDDEN  = 0x1;
    private const int CRYPTPROTECT_LOCAL_MACHINE = 0x4;

    /// <summary>
    /// Initializes empty prompt structure.
    /// </summary>
    /// <param name="ps">
    /// Prompt parameter (which we do not actually need).
    /// </param>
    private static void InitPrompt(ref CRYPTPROTECT_PROMPTSTRUCT ps)
    {
        ps.cbSize       = Marshal.SizeOf(
                                  typeof(CRYPTPROTECT_PROMPTSTRUCT));
        ps.dwPromptFlags= 0;
        ps.hwndApp      = NullPtr;
        ps.szPrompt     = null;
    }

    /// <summary>
    /// Initializes a BLOB structure from a byte array.
    /// </summary>
    /// <param name="data">
    /// Original data in a byte array format.
    /// </param>
    /// <param name="blob">
    /// Returned blob structure.
    /// </param>
    private static void InitBLOB(byte[] data, ref DATA_BLOB blob)
    {
        // Use empty array for null parameter.
        if (data == null)
            data = new byte[0];
            
        // Allocate memory for the BLOB data.
        blob.pbData = Marshal.AllocHGlobal(data.Length);

        // Make sure that memory allocation was successful.
        if (blob.pbData == IntPtr.Zero)
            throw new Exception(
                "Unable to allocate data buffer for BLOB structure.");

        // Specify number of bytes in the BLOB.
        blob.cbData = data.Length;

        // Copy data from original source to the BLOB structure.
        Marshal.Copy(data, 0, blob.pbData, data.Length);
    }

    // Flag indicating the type of key. DPAPI terminology refers to
    // key types as user store or machine store.
    public enum KeyType {UserKey = 1, MachineKey};

    // It is reasonable to set default key type to user key.
    private static KeyType defaultKeyType = KeyType.UserKey;

    /// <summary>
    /// Calls DPAPI CryptProtectData function to encrypt a plaintext
    /// string value with a user-specific key. This function does not
    /// specify data description and additional entropy.
    /// </summary>
    /// <param name="plainText">
    /// Plaintext data to be encrypted.
    /// </param>
    /// <returns>
    /// Encrypted value in a base64-encoded format.
    /// </returns>
    public static string Encrypt(string plainText)
    {
        return Encrypt(defaultKeyType, plainText, String.Empty,
                        String.Empty);
    }

    /// <summary>
    /// Calls DPAPI CryptProtectData function to encrypt a plaintext
    /// string value. This function does not specify data description
    /// and additional entropy.
    /// </summary>
    /// <param name="keyType">
    /// Defines type of encryption key to use. When user key is
    /// specified, any application running under the same user account
    /// as the one making this call, will be able to decrypt data.
    /// Machine key will allow any application running on the same
    /// computer where data were encrypted to perform decryption.
    /// Note: If optional entropy is specifed, it will be required
    /// for decryption.
    /// </param>
    /// <param name="plainText">
    /// Plaintext data to be encrypted.
    /// </param>
    /// <returns>
    /// Encrypted value in a base64-encoded format.
    /// </returns>
    public static string Encrypt(KeyType keyType, string plainText)
    {
        return Encrypt(keyType, plainText, String.Empty,
                        String.Empty);
    }

    /// <summary>
    /// Calls DPAPI CryptProtectData function to encrypt a plaintext
    /// string value. This function does not specify data description.
    /// </summary>
    /// <param name="keyType">
    /// Defines type of encryption key to use. When user key is
    /// specified, any application running under the same user account
    /// as the one making this call, will be able to decrypt data.
    /// Machine key will allow any application running on the same
    /// computer where data were encrypted to perform decryption.
    /// Note: If optional entropy is specifed, it will be required
    /// for decryption.
    /// </param>
    /// <param name="plainText">
    /// Plaintext data to be encrypted.
    /// </param>
    /// <param name="entropy">
    /// Optional entropy which - if specified - will be required to
    /// perform decryption.
    /// </param>
    /// <returns>
    /// Encrypted value in a base64-encoded format.
    /// </returns>
    public static string Encrypt(KeyType keyType,
                                 string  plainText,
                                 string  entropy)
    {
        return Encrypt(keyType, plainText, entropy, String.Empty);
    }

    /// <summary>
    /// Calls DPAPI CryptProtectData function to encrypt a plaintext
    /// string value.
    /// </summary>
    /// <param name="keyType">
    /// Defines type of encryption key to use. When user key is
    /// specified, any application running under the same user account
    /// as the one making this call, will be able to decrypt data.
    /// Machine key will allow any application running on the same
    /// computer where data were encrypted to perform decryption.
    /// Note: If optional entropy is specifed, it will be required
    /// for decryption.
    /// </param>
    /// <param name="plainText">
    /// Plaintext data to be encrypted.
    /// </param>
    /// <param name="entropy">
    /// Optional entropy which - if specified - will be required to
    /// perform decryption.
    /// </param>
    /// <param name="description">
    /// Optional description of data to be encrypted. If this value is
    /// specified, it will be stored along with encrypted data and
    /// returned as a separate value during decryption.
    /// </param>
    /// <returns>
    /// Encrypted value in a base64-encoded format.
    /// </returns>
    public static string Encrypt(KeyType keyType,
                                 string  plainText,
                                 string  entropy,
                                 string  description)
    {
        // Make sure that parameters are valid.
        if (plainText == null) plainText = String.Empty;
        if (entropy   == null) entropy   = String.Empty;

        // Call encryption routine and convert returned bytes into
        // a base64-encoded value.
        return Convert.ToBase64String(
                Encrypt(keyType,
                        Encoding.UTF8.GetBytes(plainText),
                        Encoding.UTF8.GetBytes(entropy),
                        description));
    }

    /// <summary>
    /// Calls DPAPI CryptProtectData function to encrypt an array of
    /// plaintext bytes.
    /// </summary>
    /// <param name="keyType">
    /// Defines type of encryption key to use. When user key is
    /// specified, any application running under the same user account
    /// as the one making this call, will be able to decrypt data.
    /// Machine key will allow any application running on the same
    /// computer where data were encrypted to perform decryption.
    /// Note: If optional entropy is specifed, it will be required
    /// for decryption.
    /// </param>
    /// <param name="plainTextBytes">
    /// Plaintext data to be encrypted.
    /// </param>
    /// <param name="entropyBytes">
    /// Optional entropy which - if specified - will be required to
    /// perform decryption.
    /// </param>
    /// <param name="description">
    /// Optional description of data to be encrypted. If this value is
    /// specified, it will be stored along with encrypted data and
    /// returned as a separate value during decryption.
    /// </param>
    /// <returns>
    /// Encrypted value.
    /// </returns>
    public static byte[] Encrypt(KeyType keyType,
                                 byte[]  plainTextBytes,
                                 byte[]  entropyBytes,
                                 string  description)
    {
        // Make sure that parameters are valid.
        if (plainTextBytes == null) plainTextBytes = new byte[0];
        if (entropyBytes   == null) entropyBytes   = new byte[0];
        if (description    == null) description    = String.Empty;

        // Create BLOBs to hold data.
        DATA_BLOB plainTextBlob  = new DATA_BLOB();
        DATA_BLOB cipherTextBlob = new DATA_BLOB();
        DATA_BLOB entropyBlob    = new DATA_BLOB();

        // We only need prompt structure because it is a required
        // parameter.
        CRYPTPROTECT_PROMPTSTRUCT prompt =
                                  new CRYPTPROTECT_PROMPTSTRUCT();
        InitPrompt(ref prompt);

        try
        {
            // Convert plaintext bytes into a BLOB structure.
            try
            {
                InitBLOB(plainTextBytes, ref plainTextBlob);
            }
            catch (Exception ex)
            {
                throw new Exception(
                    "Cannot initialize plaintext BLOB.", ex);
            }

            // Convert entropy bytes into a BLOB structure.
            try
            {
                InitBLOB(entropyBytes, ref entropyBlob);
            }
            catch (Exception ex)
            {
                throw new Exception(
                    "Cannot initialize entropy BLOB.", ex);
            }

            // Disable any types of UI.
            int flags = CRYPTPROTECT_UI_FORBIDDEN;

            // When using machine-specific key, set up machine flag.
            if (keyType == KeyType.MachineKey)
                flags |= CRYPTPROTECT_LOCAL_MACHINE;

            // Call DPAPI to encrypt data.
            bool success = CryptProtectData(ref plainTextBlob,
                                                description,
                                            ref entropyBlob,
                                                IntPtr.Zero,
                                            ref prompt,
                                                flags,
                                            ref cipherTextBlob);
            // Check the result.
            if (!success)
            {
                // If operation failed, retrieve last Win32 error.
                int errCode = Marshal.GetLastWin32Error();

                // Win32Exception will contain error message corresponding
                // to the Windows error code.
                throw new Exception(
                    "CryptProtectData failed.", new Win32Exception(errCode));
            }

            // Allocate memory to hold ciphertext.
            byte[] cipherTextBytes = new byte[cipherTextBlob.cbData];

            // Copy ciphertext from the BLOB to a byte array.
            Marshal.Copy(cipherTextBlob.pbData,
                            cipherTextBytes,
                            0,
                            cipherTextBlob.cbData);

            // Return the result.
            return cipherTextBytes;
        }
        catch (Exception ex)
        {
            throw new Exception("DPAPI was unable to encrypt data.", ex);
        }
        // Free all memory allocated for BLOBs.
        finally
        {
            if (plainTextBlob.pbData != IntPtr.Zero)
                Marshal.FreeHGlobal(plainTextBlob.pbData);

            if (cipherTextBlob.pbData != IntPtr.Zero)
                Marshal.FreeHGlobal(cipherTextBlob.pbData);

            if (entropyBlob.pbData != IntPtr.Zero)
                Marshal.FreeHGlobal(entropyBlob.pbData);
        }
    }

    /// <summary>
    /// Calls DPAPI CryptUnprotectData to decrypt ciphertext bytes.
    /// This function does not use additional entropy and does not
    /// return data description.
    /// </summary>
    /// <param name="cipherText">
    /// Encrypted data formatted as a base64-encoded string.
    /// </param>
    /// <returns>
    /// Decrypted data returned as a UTF-8 string.
    /// </returns>
    /// <remarks>
    /// When decrypting data, it is not necessary to specify which
    /// type of encryption key to use: user-specific or
    /// machine-specific; DPAPI will figure it out by looking at
    /// the signature of encrypted data.
    /// </remarks>
    public static string Decrypt(string cipherText)
    {
        string description;

        return Decrypt(cipherText, String.Empty, out description);
    }

    /// <summary>
    /// Calls DPAPI CryptUnprotectData to decrypt ciphertext bytes.
    /// This function does not use additional entropy.
    /// </summary>
    /// <param name="cipherText">
    /// Encrypted data formatted as a base64-encoded string.
    /// </param>
    /// <param name="description">
    /// Returned description of data specified during encryption.
    /// </param>
    /// <returns>
    /// Decrypted data returned as a UTF-8 string.
    /// </returns>
    /// <remarks>
    /// When decrypting data, it is not necessary to specify which
    /// type of encryption key to use: user-specific or
    /// machine-specific; DPAPI will figure it out by looking at
    /// the signature of encrypted data.
    /// </remarks>
    public static string Decrypt(    string cipherText,
                                 out string description)
    {
        return Decrypt(cipherText, String.Empty, out description);
    }

    /// <summary>
    /// Calls DPAPI CryptUnprotectData to decrypt ciphertext bytes.
    /// </summary>
    /// <param name="cipherText">
    /// Encrypted data formatted as a base64-encoded string.
    /// </param>
    /// <param name="entropy">
    /// Optional entropy, which is required if it was specified during
    /// encryption.
    /// </param>
    /// <param name="description">
    /// Returned description of data specified during encryption.
    /// </param>
    /// <returns>
    /// Decrypted data returned as a UTF-8 string.
    /// </returns>
    /// <remarks>
    /// When decrypting data, it is not necessary to specify which
    /// type of encryption key to use: user-specific or
    /// machine-specific; DPAPI will figure it out by looking at
    /// the signature of encrypted data.
    /// </remarks>
    public static string Decrypt(    string cipherText,
                                     string entropy,
                                 out string description)
    {
        // Make sure that parameters are valid.
        if (entropy == null) entropy = String.Empty;

        return Encoding.UTF8.GetString(
                    Decrypt(    Convert.FromBase64String(cipherText),
                                Encoding.UTF8.GetBytes(entropy),
                            out description));
    }

    /// <summary>
    /// Calls DPAPI CryptUnprotectData to decrypt ciphertext bytes.
    /// </summary>
    /// <param name="cipherTextBytes">
    /// Encrypted data.
    /// </param>
    /// <param name="entropyBytes">
    /// Optional entropy, which is required if it was specified during
    /// encryption.
    /// </param>
    /// <param name="description">
    /// Returned description of data specified during encryption.
    /// </param>
    /// <returns>
    /// Decrypted data bytes.
    /// </returns>
    /// <remarks>
    /// When decrypting data, it is not necessary to specify which
    /// type of encryption key to use: user-specific or
    /// machine-specific; DPAPI will figure it out by looking at
    /// the signature of encrypted data.
    /// </remarks>
    public static byte[] Decrypt(    byte[] cipherTextBytes,
                                     byte[] entropyBytes,
                                 out string description)
    {
        // Create BLOBs to hold data.
        DATA_BLOB plainTextBlob  = new DATA_BLOB();
        DATA_BLOB cipherTextBlob = new DATA_BLOB();
        DATA_BLOB entropyBlob    = new DATA_BLOB();

        // We only need prompt structure because it is a required
        // parameter.
        CRYPTPROTECT_PROMPTSTRUCT prompt =
                                  new CRYPTPROTECT_PROMPTSTRUCT();
        InitPrompt(ref prompt);

        // Initialize description string.
        description = String.Empty;

        try
        {
            // Convert ciphertext bytes into a BLOB structure.
            try
            {
                InitBLOB(cipherTextBytes, ref cipherTextBlob);
            }
            catch (Exception ex)
            {
                throw new Exception(
                    "Cannot initialize ciphertext BLOB.", ex);
            }

            // Convert entropy bytes into a BLOB structure.
            try
            {
                InitBLOB(entropyBytes, ref entropyBlob);
            }
            catch (Exception ex)
            {
                throw new Exception(
                    "Cannot initialize entropy BLOB.", ex);
            }

            // Disable any types of UI. CryptUnprotectData does not
            // mention CRYPTPROTECT_LOCAL_MACHINE flag in the list of
            // supported flags so we will not set it up.
            int flags = CRYPTPROTECT_UI_FORBIDDEN;

            // Call DPAPI to decrypt data.
            bool success = CryptUnprotectData(ref cipherTextBlob,
                                              ref description,
                                              ref entropyBlob,
                                                  IntPtr.Zero,
                                              ref prompt,
                                                  flags,
                                              ref plainTextBlob);

            // Check the result.
            if (!success)
            {
                // If operation failed, retrieve last Win32 error.
                int errCode = Marshal.GetLastWin32Error();

                // Win32Exception will contain error message corresponding
                // to the Windows error code.
                throw new Exception(
                    "CryptUnprotectData failed.", new Win32Exception(errCode));
            }

            // Allocate memory to hold plaintext.
            byte[] plainTextBytes = new byte[plainTextBlob.cbData];

            // Copy ciphertext from the BLOB to a byte array.
            Marshal.Copy(plainTextBlob.pbData,
                         plainTextBytes,
                         0,
                         plainTextBlob.cbData);

            // Return the result.
            return plainTextBytes;
        }
        catch (Exception ex)
        {
            throw new Exception("DPAPI was unable to decrypt data.", ex);
        }
        // Free all memory allocated for BLOBs.
        finally
        {
            if (plainTextBlob.pbData != IntPtr.Zero)
                Marshal.FreeHGlobal(plainTextBlob.pbData);

            if (cipherTextBlob.pbData != IntPtr.Zero)
                Marshal.FreeHGlobal(cipherTextBlob.pbData);

            if (entropyBlob.pbData != IntPtr.Zero)
                Marshal.FreeHGlobal(entropyBlob.pbData);
        }
    }
}

/// <summary>
/// Demonstrates the use of DPAPI functions to encrypt and decrypt data.
/// </summary>
public class DPAPITest
{
    /// <summary>
    /// The main entry point for the application.
    /// </summary>
    [STAThread]
    static void Main(string[] args)
    {
        try
        {
            string text    = "Hello, world!";
            string entropy = null;
            string description;

            Console.WriteLine("Plaintext: {0}\r\n", text);

            // Call DPAPI to encrypt data with user-specific key.
            string encrypted = DPAPI.Encrypt( DPAPI.KeyType.UserKey,
                                              text,
                                              entropy,
                                              "My Data");
            Console.WriteLine("Encrypted: {0}\r\n", encrypted);

            // Call DPAPI to decrypt data.
            string decrypted = DPAPI.Decrypt(   encrypted,
                                                entropy,
                                            out description);
            Console.WriteLine("Decrypted: {0} <<<{1}>>>\r\n",
                               decrypted, description);
        }
        catch (Exception ex)
        {
            while (ex != null)
            {
                Console.WriteLine(ex.Message);
                ex = ex.InnerException;
            }
        }
    }
}
//
// END OF FILE
///////////////////////////////////////////////////////////////////////////////
```

## VB.NET code sample
``` VB
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' SAMPLE: Encryption and decryption using DPAPI functions.
'
' To run this sample, create a new Visual Basic.NET project using the Console
' Application template and replace the contents of the Module1.vb file with
' the code below.
'
' THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
' KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
' IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
' PURPOSE.
'
' Copyright (C) 2003 Obviex(TM). All rights reserved.
'
Imports System
Imports System.Text
Imports System.Runtime.InteropServices
Imports System.ComponentModel
Imports Microsoft.VisualBasic

Public Module Module1

' <summary>
' Encrypts and decrypts data using DPAPI functions.
' </summary>
Public Class DPAPI

    ' Wrapper for DPAPI CryptProtectData function.
    <DllImport("crypt32.dll", SetLastError:=True, CharSet:=CharSet.Auto)> _
    Private Shared Function CryptProtectData _
    ( _
        ByRef pPlainText    As DATA_BLOB, _
        ByVal szDescription As String, _
        ByRef pEntropy      As DATA_BLOB, _
        ByVal pReserved     As IntPtr, _
        ByRef pPrompt       As CRYPTPROTECT_PROMPTSTRUCT, _
        ByVal dwFlags       As Integer, _
        ByRef pCipherText   As DATA_BLOB _
    ) As Boolean
    End Function

    ' Wrapper for DPAPI CryptUnprotectData function.
    <DllImport("crypt32.dll", SetLastError:=True, CharSet:=CharSet.Auto)> _
    Private Shared Function CryptUnprotectData _
    ( _
        ByRef pCipherText    As DATA_BLOB, _
        ByRef pszDescription As String, _
        ByRef pEntropy       As DATA_BLOB, _
        ByVal pReserved      As IntPtr, _
        ByRef pPrompt        As CRYPTPROTECT_PROMPTSTRUCT, _
        ByVal dwFlags        As Integer, _
        ByRef pPlainText     As DATA_BLOB _
    ) As Boolean
    End Function

    ' BLOB structure used to pass data to DPAPI functions.
    <StructLayout(LayoutKind.Sequential, CharSet:=CharSet.Unicode)> _
    Friend Structure DATA_BLOB
        Public cbData As Integer
        Public pbData As IntPtr
    End Structure

    ' Prompt structure to be used for required parameters.
    <StructLayout(LayoutKind.Sequential, CharSet:=CharSet.Unicode)> _
    Friend Structure CRYPTPROTECT_PROMPTSTRUCT
        Public cbSize        As Integer
        Public dwPromptFlags As Integer
        Public hwndApp       As IntPtr
        Public szPrompt      As String
    End Structure

    ' DPAPI key initialization flags.
    Private Const CRYPTPROTECT_UI_FORBIDDEN  As Integer = 1
    Private Const CRYPTPROTECT_LOCAL_MACHINE As Integer = 4

    ' <summary>
    ' Initializes empty prompt structure.
    ' </summary>
    ' <param name="ps">
    ' Prompt parameter (which we do not actually need).
    ' </param>
    Private Shared Sub InitPrompt _
    ( _
        ByRef ps As CRYPTPROTECT_PROMPTSTRUCT _
    )
        ps.cbSize        = Marshal.SizeOf(GetType(CRYPTPROTECT_PROMPTSTRUCT))
        ps.dwPromptFlags = 0
        ps.hwndApp       = IntPtr.Zero
        ps.szPrompt      = Nothing
    End Sub

    ' <summary>
    ' Initializes a BLOB structure from a byte array.
    ' </summary>
    ' <param name="data">
    ' Original data in a byte array format.
    ' </param>
    ' <param name="blob">
    ' Returned blob structure.
    ' </param>
    Private Shared Sub InitBLOB _
    ( _
        ByVal data As Byte(), _
        ByRef blob As DATA_BLOB _
    )
        ' Use empty array for null parameter.
        If data Is Nothing Then
            data = New Byte(0){}
        End If
            
        ' Allocate memory for the BLOB data.
        blob.pbData = Marshal.AllocHGlobal(data.Length)

        ' Make sure that memory allocation was successful.
        If blob.pbData.Equals(IntPtr.Zero) Then
            Throw New Exception( _
                    "Unable to allocate data buffer for BLOB structure.")
        End If

        ' Specify number of bytes in the BLOB.
        blob.cbData = data.Length
        Marshal.Copy(data, 0, blob.pbData, data.Length)
    End Sub

    ' Flag indicating the type of key. DPAPI terminology refers to
    ' key types as user store or machine store.
    Public Enum KeyType
        UserKey = 1
        MachineKey
    End Enum

    ' It is reasonable to set default key type to user key.
    Private Shared defaultKeyType As KeyType = KeyType.UserKey

    ' <summary>
    ' Calls DPAPI CryptProtectData function to encrypt a plaintext
    ' string value with a user-specific key. This function does not
    ' specify data description and additional entropy.
    ' </summary>
    ' <param name="plainText">
    ' Plaintext data to be encrypted.
    ' </param>
    ' <returns>
    ' Encrypted value in a base64-encoded format.
    ' </returns>
    Public Shared Function Encrypt _
    ( _
        ByVal plainText As String _
    ) As String
        Return Encrypt(defaultKeyType, plainText, String.Empty, String.Empty)
    End Function

    ' <summary>
    ' Calls DPAPI CryptProtectData function to encrypt a plaintext
    ' string value. This function does not specify data description
    ' and additional entropy.
    ' </summary>
    ' <param name="keyType">
    ' Defines type of encryption key to use. When user key is
    ' specified, any application running under the same user account
    ' as the one making this call, will be able to decrypt data.
    ' Machine key will allow any application running on the same
    ' computer where data were encrypted to perform decryption.
    ' Note: If optional entropy is specifed, it will be required
    ' for decryption.
    ' </param>
    ' <param name="plainText">
    ' Plaintext data to be encrypted.
    ' </param>
    ' <returns>
    ' Encrypted value in a base64-encoded format.
    ' </returns>
    Public Shared Function Encrypt _
    ( _
        ByVal keyType   As KeyType, _
        ByVal plainText As String _
    ) As String
        Return Encrypt(keyType, plainText, String.Empty, String.Empty)
    End Function

    Public Shared Function Encrypt _
    ( _
        ByVal keyType   As KeyType, _
        ByVal plainText As String, _
        ByVal entropy   As String _
    ) As String
        Return Encrypt(keyType, plainText, entropy, String.Empty)
    End Function

    ' <summary>
    ' Calls DPAPI CryptProtectData function to encrypt a plaintext
    ' string value. This function does not specify data description.
    ' </summary>
    ' <param name="keyType">
    ' Defines type of encryption key to use. When user key is
    ' specified, any application running under the same user account
    ' as the one making this call, will be able to decrypt data.
    ' Machine key will allow any application running on the same
    ' computer where data were encrypted to perform decryption.
    ' Note: If optional entropy is specifed, it will be required
    ' for decryption.
    ' </param>
    ' <param name="plainText">
    ' Plaintext data to be encrypted.
    ' </param>
    ' <param name="entropy">
    ' Optional entropy which - if specified - will be required to
    ' perform decryption.
    ' </param>
    ' <returns>
    ' Encrypted value in a base64-encoded format.
    ' </returns>
    Public Shared Function Encrypt _
    ( _
        ByVal keyType     As KeyType, _
        ByVal plainText   As String, _
        ByVal entropy     As String, _
        ByVal description As String _
    ) As String
        If plainText Is Nothing Then
            plainText = String.Empty
        End If
        If entropy Is Nothing Then
            entropy = String.Empty
        End If
        Return Convert.ToBase64String( _
            Encrypt(keyType, _
                    Encoding.UTF8.GetBytes(plainText), _
                    Encoding.UTF8.GetBytes(entropy), _
                    description))
    End Function

    ' <summary>
    ' Calls DPAPI CryptProtectData function to encrypt an array of
    ' plaintext bytes.
    ' </summary>
    ' <param name="keyType">
    ' Defines type of encryption key to use. When user key is
    ' specified, any application running under the same user account
    ' as the one making this call, will be able to decrypt data.
    ' Machine key will allow any application running on the same
    ' computer where data were encrypted to perform decryption.
    ' Note: If optional entropy is specifed, it will be required
    ' for decryption.
    ' </param>
    ' <param name="plainTextBytes">
    ' Plaintext data to be encrypted.
    ' </param>
    ' <param name="entropyBytes">
    ' Optional entropy which - if specified - will be required to
    ' perform decryption.
    ' </param>
    ' <param name="description">
    ' Optional description of data to be encrypted. If this value is
    ' specified, it will be stored along with encrypted data and
    ' returned as a separate value during decryption.
    ' </param>
    ' <returns>
    ' Encrypted value.
    ' </returns>
    Public Shared Function Encrypt _
    ( _
        ByVal keyType        As KeyType, _
        ByVal plainTextBytes As Byte(), _
        ByVal entropyBytes   As Byte(), _
        ByVal description    As String _
    ) As Byte()
        ' Make sure that parameters are valid.
        If plainTextBytes Is Nothing Then
            plainTextBytes = New Byte(0){}
        End If

        If entropyBytes Is Nothing Then
            entropyBytes = New Byte(0){}
        End If

        If description Is Nothing Then
            description = String.Empty
        End If

        ' Create BLOBs to hold data.
        Dim plainTextBlob As DATA_BLOB = New DATA_BLOB
        Dim cipherTextBlob As DATA_BLOB = New DATA_BLOB
        Dim entropyBlob As DATA_BLOB = New DATA_BLOB

        ' We only need prompt structure because it is a required
        ' parameter.
        Dim prompt As _
                CRYPTPROTECT_PROMPTSTRUCT = New CRYPTPROTECT_PROMPTSTRUCT
        InitPrompt(prompt)

        Try
            ' Convert plaintext bytes into a BLOB structure.
            Try
                InitBLOB(plainTextBytes, plainTextBlob)
            Catch ex As Exception
                Throw New Exception("Cannot initialize plaintext BLOB.", ex)
            End Try

            ' Convert entropy bytes into a BLOB structure.
            Try
                InitBLOB(entropyBytes, entropyBlob)
            Catch ex As Exception
                Throw New Exception("Cannot initialize entropy BLOB.", ex)
            End Try

            ' Disable any types of UI.
            Dim flags As Integer = CRYPTPROTECT_UI_FORBIDDEN

            ' When using machine-specific key, set up machine flag.
            If keyType = KeyType.MachineKey Then
                flags = flags Or (CRYPTPROTECT_LOCAL_MACHINE)
            End If

            ' Call DPAPI to encrypt data.
            Dim success As Boolean = CryptProtectData( _
                                            plainTextBlob, _
                                            description, _
                                            entropyBlob, _
                                            IntPtr.Zero, _
                                            prompt, _
                                            flags, _
                                            cipherTextBlob)

            ' Check the result.
            If Not success Then
                ' If operation failed, retrieve last Win32 error.
                Dim errCode As Integer = Marshal.GetLastWin32Error()
     
                ' Win32Exception will contain error message corresponding
                ' to the Windows error code.
                Throw New Exception("CryptProtectData failed.", _
                                New Win32Exception(errCode))
            End If

            ' Allocate memory to hold ciphertext.
            Dim cipherTextBytes(cipherTextBlob.cbData-1) As Byte

            ' Copy ciphertext from the BLOB to a byte array.
            Marshal.Copy(cipherTextBlob.pbData, cipherTextBytes, 0, _
                            cipherTextBlob.cbData)

            ' Return the result.
            Return cipherTextBytes
        Catch ex As Exception
            Throw New Exception("DPAPI was unable to encrypt data.", ex)
        Finally
            If Not(plainTextBlob.pbData.Equals(IntPtr.Zero)) Then
                Marshal.FreeHGlobal(plainTextBlob.pbData)
            End If

            If Not (cipherTextBlob.pbData.Equals(IntPtr.Zero)) Then
                Marshal.FreeHGlobal(cipherTextBlob.pbData)
            End If

            If Not(entropyBlob.pbData.Equals(IntPtr.Zero)) Then
                Marshal.FreeHGlobal(entropyBlob.pbData)
            End If
        End Try
    End Function

    ' <summary>
    ' Calls DPAPI CryptUnprotectData to decrypt ciphertext bytes.
    ' This function does not use additional entropy and does not
    ' return data description.
    ' </summary>
    ' <param name="cipherText">
    ' Encrypted data formatted as a base64-encoded string.
    ' </param>
    ' <returns>
    ' Decrypted data returned as a UTF-8 string.
    ' </returns>
    ' <remarks>
    ' When decrypting data, it is not necessary to specify which
    ' type of encryption key to use: user-specific or
    ' machine-specific; DPAPI will figure it out by looking at
    ' the signature of encrypted data.
    ' </remarks>
    Public Shared Function Decrypt _
    ( _
        ByVal cipherText As String _
    ) As String
        Dim description As String
        Return Decrypt(cipherText, String.Empty, description)
    End Function

    ' <summary>
    ' Calls DPAPI CryptUnprotectData to decrypt ciphertext bytes.
    ' This function does not use additional entropy.
    ' </summary>
    ' <param name="cipherText">
    ' Encrypted data formatted as a base64-encoded string.
    ' </param>
    ' <param name="description">
    ' Returned description of data specified during encryption.
    ' </param>
    ' <returns>
    ' Decrypted data returned as a UTF-8 string.
    ' </returns>
    ' <remarks>
    ' When decrypting data, it is not necessary to specify which
    ' type of encryption key to use: user-specific or
    ' machine-specific; DPAPI will figure it out by looking at
    ' the signature of encrypted data.
    ' </remarks>
    Public Shared Function Decrypt _
    ( _
        ByVal cipherText  As String, _
        ByRef description As String _
    ) As String
        Return Decrypt(cipherText, String.Empty, description)
    End Function

    ' <summary>
    ' Calls DPAPI CryptUnprotectData to decrypt ciphertext bytes.
    ' </summary>
    ' <param name="cipherText">
    ' Encrypted data formatted as a base64-encoded string.
    ' </param>
    ' <param name="entropy">
    ' Optional entropy, which is required if it was specified during
    ' encryption.
    ' </param>
    ' <param name="description">
    ' Returned description of data specified during encryption.
    ' </param>
    ' <returns>
    ' Decrypted data returned as a UTF-8 string.
    ' </returns>
    ' <remarks>
    ' When decrypting data, it is not necessary to specify which
    ' type of encryption key to use: user-specific or
    ' machine-specific; DPAPI will figure it out by looking at
    ' the signature of encrypted data.
    ' </remarks>
    Public Shared Function Decrypt _
    ( _
        ByVal cipherText  As String, _
        ByVal entropy     As String, _
        ByRef description As String _
    ) As String
        ' Make sure that parameters are valid.
        If entropy Is Nothing Then
            entropy = String.Empty
        End If

        Return Encoding.UTF8.GetString( _
            Decrypt(Convert.FromBase64String(cipherText), _
                    Encoding.UTF8.GetBytes(entropy), description))
    End Function

    ' <summary>
    ' Calls DPAPI CryptUnprotectData to decrypt ciphertext bytes.
    ' </summary>
    ' <param name="cipherTextBytes">
    ' Encrypted data.
    ' </param>
    ' <param name="entropyBytes">
    ' Optional entropy, which is required if it was specified during
    ' encryption.
    ' </param>
    ' <param name="description">
    ' Returned description of data specified during encryption.
    ' </param>
    ' <returns>
    ' Decrypted data bytes.
    ' </returns>
    ' <remarks>
    ' When decrypting data, it is not necessary to specify which
    ' type of encryption key to use: user-specific or
    ' machine-specific; DPAPI will figure it out by looking at
    ' the signature of encrypted data.
    ' </remarks>
    Public Shared Function Decrypt _
    ( _
        ByVal cipherTextBytes As Byte(), _
        ByVal entropyBytes As Byte(), _
        ByRef description As String _
    ) As Byte()

        ' Create BLOBs to hold data.
        Dim plainTextBlob  As DATA_BLOB = New DATA_BLOB
        Dim cipherTextBlob As DATA_BLOB = New DATA_BLOB
        Dim entropyBlob    As DATA_BLOB = New DATA_BLOB

        ' We only need prompt structure because it is a required
        ' parameter.
        Dim prompt As _
                CRYPTPROTECT_PROMPTSTRUCT = New CRYPTPROTECT_PROMPTSTRUCT
        InitPrompt(prompt)
       
        ' Initialize description string.
        description = String.Empty

        Try
            ' Convert ciphertext bytes into a BLOB structure.
            Try
                InitBLOB(cipherTextBytes, cipherTextBlob)
            Catch ex As Exception
                Throw New Exception("Cannot initialize ciphertext BLOB.", ex)
            End Try

            ' Convert entropy bytes into a BLOB structure.
            Try
                InitBLOB(entropyBytes, entropyBlob)
            Catch ex As Exception
                Throw New Exception("Cannot initialize entropy BLOB.", ex)
            End Try

            ' Disable any types of UI. CryptUnprotectData does not
            ' mention CRYPTPROTECT_LOCAL_MACHINE flag in the list of
            ' supported flags so we will not set it up.
            Dim flags As Integer = CRYPTPROTECT_UI_FORBIDDEN
           
            ' Call DPAPI to decrypt data.
            Dim success As Boolean = CryptUnprotectData( _
                                            cipherTextBlob, _
                                            description, _
                                            entropyBlob, _
                                            IntPtr.Zero, _
                                            prompt, _
                                            flags, _
                                            plainTextBlob)

            ' Check the result.
            If Not success Then
                ' If operation failed, retrieve last Win32 error.
                Dim errCode As Integer = Marshal.GetLastWin32Error()

                ' Win32Exception will contain error message corresponding
                ' to the Windows error code.
                Throw New Exception("CryptUnprotectData failed.", _
                            New Win32Exception(errCode))
            End If

            ' Allocate memory to hold plaintext.
            Dim plainTextBytes(plainTextBlob.cbData-1) As Byte

            ' Copy ciphertext from the BLOB to a byte array.
            Marshal.Copy(plainTextBlob.pbData, plainTextBytes, 0, _
                            plainTextBlob.cbData)

            ' Return the result.
            Return plainTextBytes
        Catch ex As Exception
            Throw New Exception("DPAPI was unable to decrypt data.", ex)
        ' Free all memory allocated for BLOBs.
        Finally
            If Not(plainTextBlob.pbData.Equals(IntPtr.Zero)) Then
                Marshal.FreeHGlobal(plainTextBlob.pbData)
            End If

            If Not(cipherTextBlob.pbData.Equals(IntPtr.Zero)) Then
                Marshal.FreeHGlobal(cipherTextBlob.pbData)
            End If

            If Not(entropyBlob.pbData.Equals(IntPtr.Zero)) Then
                Marshal.FreeHGlobal(entropyBlob.pbData)
            End If
        End Try
    End Function
End Class

' <summary>
' The main entry point for the application.
' </summary>
Sub Main(ByVal args As String())
    Try
        Dim text        As String = "Hello, world!"
        Dim entropy     As String = Nothing
        Dim description As String
        Dim encrypted   As String
        Dim decrypted   As String

        Console.WriteLine("Plaintext: {0}" & Chr(13) & Chr(10), text)

        ' Call DPAPI to encrypt data with user-specific key.
        encrypted  = DPAPI.Encrypt( DPAPI.KeyType.UserKey, _
                                    text, entropy, "My Data")

        Console.WriteLine("Encrypted: {0}" & Chr(13) & Chr(10), encrypted)

        ' Call DPAPI to decrypt data.
        decrypted = DPAPI.Decrypt(encrypted, entropy, description)

        Console.WriteLine("Decrypted: {0} <<<{1}>>>" & Chr(13) & Chr(10), _
                            decrypted, description)
    Catch ex As Exception
        While Not (ex Is Nothing)
            Console.WriteLine(ex.Message)
            ex = ex.InnerException
        End While
    End Try
End Sub

End Module
'
' END OF FILE
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
```

## Program output
```
Plaintext: Hello, world!

Encrypted: AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA/n...AAAAD3e2CVOMOk3awsn7mR7NdMubogt

Decrypted: Hello, world! <<<My Data>>>
```
