# How to generate a random password in C# or VB.NET

## Description
These code samples demonstrate how to generate a strong random password, which does not contain ambiguous characters (such as [1,l,I] or [O,0]). A strong password must be at least eight characters long and contain a combination of lower- and upper-case letters, numbers, and special characters.

## Disclaimer
These code samples are provided for demonstration purpose only. Use at your own risk.

## C# code sample
``` CSharp
///////////////////////////////////////////////////////////////////////////////
// SAMPLE: Generates random password, which complies with the strong password
//         rules and does not contain ambiguous characters.
//
// To run this sample, create a new Visual C# project using the Console
// Application template and replace the contents of the Class1.cs file with
// the code below.
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
// EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
// 
// Copyright (C) 2004 Obviex(TM). All rights reserved.
// 
using System;
using System.Security.Cryptography;

/// <summary>
/// This class can generate random passwords, which do not include ambiguous 
/// characters, such as I, l, and 1. The generated password will be made of
/// 7-bit ASCII symbols. Every four characters will include one lower case
/// character, one upper case character, one number, and one special symbol
/// (such as '%') in a random order. The password will always start with an
/// alpha-numeric character; it will not start with a special symbol (we do
/// this because some back-end systems do not like certain special
/// characters in the first position).
/// </summary>
public class RandomPassword
{
    // Define default min and max password lengths.
    private static int DEFAULT_MIN_PASSWORD_LENGTH  = 8;
    private static int DEFAULT_MAX_PASSWORD_LENGTH  = 10;

    // Define supported password characters divided into groups.
    // You can add (or remove) characters to (from) these groups.
    private static string PASSWORD_CHARS_LCASE  = "abcdefgijkmnopqrstwxyz";
    private static string PASSWORD_CHARS_UCASE  = "ABCDEFGHJKLMNPQRSTWXYZ";
    private static string PASSWORD_CHARS_NUMERIC= "23456789";
    private static string PASSWORD_CHARS_SPECIAL= "*$-+?_&=!%{}/";

    /// <summary>
    /// Generates a random password.
    /// </summary>
    /// <returns>
    /// Randomly generated password.
    /// </returns>
    /// <remarks>
    /// The length of the generated password will be determined at
    /// random. It will be no shorter than the minimum default and
    /// no longer than maximum default.
    /// </remarks>
    public static string Generate()
    {
        return Generate(DEFAULT_MIN_PASSWORD_LENGTH, 
                        DEFAULT_MAX_PASSWORD_LENGTH);
    }

    /// <summary>
    /// Generates a random password of the exact length.
    /// </summary>
    /// <param name="length">
    /// Exact password length.
    /// </param>
    /// <returns>
    /// Randomly generated password.
    /// </returns>
    public static string Generate(int length)
    {
        return Generate(length, length);
    }

    /// <summary>
    /// Generates a random password.
    /// </summary>
    /// <param name="minLength">
    /// Minimum password length.
    /// </param>
    /// <param name="maxLength">
    /// Maximum password length.
    /// </param>
    /// <returns>
    /// Randomly generated password.
    /// </returns>
    /// <remarks>
    /// The length of the generated password will be determined at
    /// random and it will fall with the range determined by the
    /// function parameters.
    /// </remarks>
    public static string Generate(int   minLength,
                                  int   maxLength)
    {
        // Make sure that input parameters are valid.
        if (minLength <= 0 || maxLength <= 0 || minLength > maxLength)
            return null;

        // Create a local array containing supported password characters
        // grouped by types. You can remove character groups from this
        // array, but doing so will weaken the password strength.
        char[][] charGroups = new char[][] 
        {
            PASSWORD_CHARS_LCASE.ToCharArray(),
            PASSWORD_CHARS_UCASE.ToCharArray(),
            PASSWORD_CHARS_NUMERIC.ToCharArray(),
            PASSWORD_CHARS_SPECIAL.ToCharArray()
        };

        // Use this array to track the number of unused characters in each
        // character group.
        int[] charsLeftInGroup = new int[charGroups.Length];

        // Initially, all characters in each group are not used.
        for (int i=0; i<charsLeftInGroup.Length; i++)
            charsLeftInGroup[i] = charGroups[i].Length;
        
        // Use this array to track (iterate through) unused character groups.
        int[] leftGroupsOrder = new int[charGroups.Length];

        // Initially, all character groups are not used.
        for (int i=0; i<leftGroupsOrder.Length; i++)
            leftGroupsOrder[i] = i;

        // Because we cannot use the default randomizer, which is based on the
        // current time (it will produce the same "random" number within a
        // second), we will use a random number generator to seed the
        // randomizer.
        
        // Use a 4-byte array to fill it with random bytes and convert it then
        // to an integer value.
        byte[] randomBytes = new byte[4];

        // Generate 4 random bytes.
        RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        rng.GetBytes(randomBytes);

        // Convert 4 bytes into a 32-bit integer value.
        int seed = BitConverter.ToInt32(randomBytes, 0);

        // Now, this is real randomization.
        Random  random  = new Random(seed);

        // This array will hold password characters.
        char[] password = null;

        // Allocate appropriate memory for the password.
        if (minLength < maxLength)
            password = new char[random.Next(minLength, maxLength+1)];
        else
            password = new char[minLength];

        // Index of the next character to be added to password.
        int nextCharIdx;
        
        // Index of the next character group to be processed.
        int nextGroupIdx;

        // Index which will be used to track not processed character groups.
        int nextLeftGroupsOrderIdx;
        
        // Index of the last non-processed character in a group.
        int lastCharIdx;

        // Index of the last non-processed group.
        int lastLeftGroupsOrderIdx = leftGroupsOrder.Length - 1;
        
        // Generate password characters one at a time.
        for (int i=0; i<password.Length; i++)
        {
            // If only one character group remained unprocessed, process it;
            // otherwise, pick a random character group from the unprocessed
            // group list. To allow a special character to appear in the
            // first position, increment the second parameter of the Next
            // function call by one, i.e. lastLeftGroupsOrderIdx + 1.
            if (lastLeftGroupsOrderIdx == 0)
                nextLeftGroupsOrderIdx = 0;
            else
                nextLeftGroupsOrderIdx = random.Next(0, 
                                                     lastLeftGroupsOrderIdx);

            // Get the actual index of the character group, from which we will
            // pick the next character.
            nextGroupIdx = leftGroupsOrder[nextLeftGroupsOrderIdx];

            // Get the index of the last unprocessed characters in this group.
            lastCharIdx = charsLeftInGroup[nextGroupIdx] - 1;
            
            // If only one unprocessed character is left, pick it; otherwise,
            // get a random character from the unused character list.
            if (lastCharIdx == 0)
                nextCharIdx = 0;
            else
                nextCharIdx = random.Next(0, lastCharIdx+1);

            // Add this character to the password.
            password[i] = charGroups[nextGroupIdx][nextCharIdx];
            
            // If we processed the last character in this group, start over.
            if (lastCharIdx == 0)
                charsLeftInGroup[nextGroupIdx] = 
                                          charGroups[nextGroupIdx].Length;
            // There are more unprocessed characters left.
            else
            {
                // Swap processed character with the last unprocessed character
                // so that we don't pick it until we process all characters in
                // this group.
                if (lastCharIdx != nextCharIdx)
                {
                    char temp = charGroups[nextGroupIdx][lastCharIdx];
                    charGroups[nextGroupIdx][lastCharIdx] = 
                                charGroups[nextGroupIdx][nextCharIdx];
                    charGroups[nextGroupIdx][nextCharIdx] = temp;
                }
                // Decrement the number of unprocessed characters in
                // this group.
                charsLeftInGroup[nextGroupIdx]--;
            }

            // If we processed the last group, start all over.
            if (lastLeftGroupsOrderIdx == 0)
                lastLeftGroupsOrderIdx = leftGroupsOrder.Length - 1;
            // There are more unprocessed groups left.
            else
            {
                // Swap processed group with the last unprocessed group
                // so that we don't pick it until we process all groups.
                if (lastLeftGroupsOrderIdx != nextLeftGroupsOrderIdx)
                {
                    int temp = leftGroupsOrder[lastLeftGroupsOrderIdx];
                    leftGroupsOrder[lastLeftGroupsOrderIdx] = 
                                leftGroupsOrder[nextLeftGroupsOrderIdx];
                    leftGroupsOrder[nextLeftGroupsOrderIdx] = temp;
                }
                // Decrement the number of unprocessed groups.
                lastLeftGroupsOrderIdx--;
            }
        }

        // Convert password characters into a string and return the result.
        return new string(password);
     }
}

/// <summary>
/// Illustrates the use of the RandomPassword class.
/// </summary>
public class RandomPasswordTest
{
    /// <summary>
    /// The main entry point for the application.
    /// </summary>
    [STAThread]
    static void Main(string[] args)
    {
        // Print 100 randomly generated passwords (8-to-10 char long).
        for (int i=0; i<100; i++)
            Console.WriteLine(RandomPassword.Generate(8, 10));
    }
}
//
// END OF FILE
///////////////////////////////////////////////////////////////////////////////
```

## VB.NET code sample
``` VB
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' SAMPLE: Generates random password, which complies with the strong password
'         rules and does not contain ambiguous characters.
'
' To run this sample, create a new Visual Basic.NET project using the Console
' Application template and replace the contents of the Module1.vb file with
' the code below.
'
' THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
' EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
' WARRANTIES OF MERCHANTABILITY AND'OR FITNESS FOR A PARTICULAR PURPOSE.
' 
' Copyright (C) 2004 Obviex(TM). All rights reserved.
' 
 Imports System
 Imports System.Security.Cryptography

 Module Module1

' <summary>
' This class can generate random passwords, which do not include ambiguous 
' characters, such as I, l, and 1. The generated password will be made of
' 7-bit ASCII symbols. Every four characters will include one lower case
' character, one upper case character, one number, and one special symbol
' (such as '%') in a random order. The password will always start with an
' alpha-numeric character; it will not start with a special symbol (we do
' this because some back-end systems do not like certain special
' characters in the first position).
' </summary>
Public Class RandomPassword

    ' Define default min and max password lengths.
    Private Shared DEFAULT_MIN_PASSWORD_LENGTH As Integer = 8
    Private Shared DEFAULT_MAX_PASSWORD_LENGTH As Integer = 10

    ' Define supported password characters divided into groups.
    ' You can add (or remove) characters to (from) these groups.
    Private Shared PASSWORD_CHARS_LCASE As String  = "abcdefgijkmnopqrstwxyz"
    Private Shared PASSWORD_CHARS_UCASE As String  = "ABCDEFGHJKLMNPQRSTWXYZ"
    Private Shared PASSWORD_CHARS_NUMERIC As String= "23456789"
    Private Shared PASSWORD_CHARS_SPECIAL As String= "*$-+?_&=!%{}/"

    ' <summary>
    ' Generates a random password.
    ' </summary>
    ' <returns>
    ' Randomly generated password.
    ' </returns>
    ' <remarks>
    ' The length of the generated password will be determined at
    ' random. It will be no shorter than the minimum default and
    ' no longer than maximum default.
    ' </remarks>
    Public Shared Function Generate() As String
        Generate = Generate(DEFAULT_MIN_PASSWORD_LENGTH, _
                            DEFAULT_MAX_PASSWORD_LENGTH)
    End Function

    ' <summary>
    ' Generates a random password of the exact length.
    ' </summary>
    ' <param name="length">
    ' Exact password length.
    ' </param>
    ' <returns>
    ' Randomly generated password.
    ' </returns>
    Public Shared Function Generate(length As Integer) As String
        Generate = Generate(length, length)
    End Function

    ' <summary>
    ' Generates a random password.
    ' </summary>
    ' <param name="minLength">
    ' Minimum password length.
    ' </param>
    ' <param name="maxLength">
    ' Maximum password length.
    ' </param>
    ' <returns>
    ' Randomly generated password.
    ' </returns>
    ' <remarks>
    ' The length of the generated password will be determined at
    ' random and it will fall with the range determined by the
    ' function parameters.
    ' </remarks>
    Public Shared Function Generate(minLength As Integer, _
                                    maxLength As Integer) _
        As String

        ' Make sure that input parameters are valid.
        If (minLength <= 0 Or maxLength <= 0 Or minLength > maxLength) Then
            Generate = Nothing
        End If

        ' Create a local array containing supported password characters
        ' grouped by types. You can remove character groups from this
        ' array, but doing so will weaken the password strength.
        Dim charGroups As Char()() = New Char()() _
        { _
            PASSWORD_CHARS_LCASE.ToCharArray(), _
            PASSWORD_CHARS_UCASE.ToCharArray(), _
            PASSWORD_CHARS_NUMERIC.ToCharArray(), _
            PASSWORD_CHARS_SPECIAL.ToCharArray() _
        }

        ' Use this array to track the number of unused characters in each
        ' character group.
        Dim charsLeftInGroup As Integer() = New Integer(charGroups.Length-1){}

        ' Initially, all characters in each group are not used.
        Dim I As Integer
        For I=0 To charsLeftInGroup.Length-1
            charsLeftInGroup(I) = charGroups(I).Length
        Next

        ' Use this array to track (iterate through) unused character groups.
        Dim leftGroupsOrder As Integer()  = New Integer(charGroups.Length-1){}

        ' Initially, all character groups are not used.
        For I=0 To leftGroupsOrder.Length-1
            leftGroupsOrder(I) = I
        Next

        ' Because we cannot use the default randomizer, which is based on the
        ' current time (it will produce the same "random" number within a
        ' second), we will use a random number generator to seed the
        ' randomizer.
        
        ' Use a 4-byte array to fill it with random bytes and convert it then
        ' to an integer value.
        Dim randomBytes As Byte() = New Byte(3){}

        ' Generate 4 random bytes.
        Dim rng As RNGCryptoServiceProvider = New RNGCryptoServiceProvider()

        rng.GetBytes(randomBytes)

        ' Convert 4 bytes into a 32-bit integer value.
        Dim seed As Integer = BitConverter.ToInt32(randomBytes, 0)

        ' Now, this is real randomization.
        Dim random As Random = New Random(seed)

        ' This array will hold password characters.
        Dim password As Char() = Nothing

        ' Allocate appropriate memory for the password.
        If (minLength < maxLength) Then
            password = New Char(random.Next(minLength-1, maxLength)){}
        Else
            password = New Char(minLength-1){}
        End If

        ' Index of the next character to be added to password.
        Dim nextCharIdx             As Integer

        ' Index of the next character group to be processed.
        Dim nextGroupIdx            As Integer

        ' Index which will be used to track not processed character groups.
        Dim nextLeftGroupsOrderIdx  As Integer

        ' Index of the last non-processed character in a group.
        Dim lastCharIdx             As Integer

        ' Index of the last non-processed group.
        Dim lastLeftGroupsOrderIdx As Integer = leftGroupsOrder.Length-1

        ' Generate password characters one at a time.
        For I=0 To password.Length-1

            ' If only one character group remained unprocessed, process it;
            ' otherwise, pick a random character group from the unprocessed
            ' group list. To allow a special character to appear in the
            ' first position, increment the second parameter of the Next
            ' function call by one, i.e. lastLeftGroupsOrderIdx + 1.
            If (lastLeftGroupsOrderIdx = 0) Then
                nextLeftGroupsOrderIdx = 0
            Else
                nextLeftGroupsOrderIdx = random.Next(0, lastLeftGroupsOrderIdx)
            End If

            ' Get the actual index of the character group, from which we will
            ' pick the next character.
            nextGroupIdx = leftGroupsOrder(nextLeftGroupsOrderIdx)

            ' Get the index of the last unprocessed characters in this group.
            lastCharIdx = charsLeftInGroup(nextGroupIdx)-1

            ' If only one unprocessed character is left, pick it; otherwise,
            ' get a random character from the unused character list.
            If (lastCharIdx = 0) Then
                nextCharIdx = 0
            Else
                nextCharIdx = random.Next(0, lastCharIdx+1)
            End If

            ' Add this character to the password.
            password(I) = charGroups(nextGroupIdx)(nextCharIdx)
            
            ' If we processed the last character in this group, start over.
            If (lastCharIdx = 0) Then
                charsLeftInGroup(nextGroupIdx) = _
                                charGroups(nextGroupIdx).Length
            ' There are more unprocessed characters left.
            Else
                ' Swap processed character with the last unprocessed character
                ' so that we don't pick it until we process all characters in
                ' this group.
                If (lastCharIdx <> nextCharIdx) Then
                    Dim temp As Char = charGroups(nextGroupIdx)(lastCharIdx)
                    charGroups(nextGroupIdx)(lastCharIdx) = _ 
                                charGroups(nextGroupIdx)(nextCharIdx)
                    charGroups(nextGroupIdx)(nextCharIdx) = temp
                End If

                ' Decrement the number of unprocessed characters in
                ' this group.
                charsLeftInGroup(nextGroupIdx) = _
                           charsLeftInGroup(nextGroupIdx)-1
            End If

            ' If we processed the last group, start all over.
            If (lastLeftGroupsOrderIdx = 0) Then
                lastLeftGroupsOrderIdx = leftGroupsOrder.Length-1
            ' There are more unprocessed groups left.
            Else
                ' Swap processed group with the last unprocessed group
                ' so that we don't pick it until we process all groups.
                If (lastLeftGroupsOrderIdx <> nextLeftGroupsOrderIdx) Then
                    Dim temp As Integer = _
                                leftGroupsOrder(lastLeftGroupsOrderIdx)
                    leftGroupsOrder(lastLeftGroupsOrderIdx) = _ 
                                leftGroupsOrder(nextLeftGroupsOrderIdx)
                    leftGroupsOrder(nextLeftGroupsOrderIdx) = temp
                End If
                
                ' Decrement the number of unprocessed groups.
                lastLeftGroupsOrderIdx = lastLeftGroupsOrderIdx - 1
            End If
        Next

        ' Convert password characters into a string and return the result.
        Generate = New String(password)
    End Function

End Class

' <summary>
' The main entry point for the application.
' </summary>
Sub Main()
    Dim I As Integer
    For I=1 To 100
        Console.WriteLine(RandomPassword.Generate(8, 10))
    Next
End Sub

End Module
'
' END OF FILE
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
```

## Program output
```
B$g3-6YpjA
Nk5{!Yb37
P}o8wX7$!
Dc5+t=Q8}P
gG_2?a4H
yW}5K3w*9
Qr9%5-jHg
8Bg%s*A63q
3Nd?E{5jxY
2Kf!s}E9
3z$XN9q*+
...
T!b68C*wt
```
