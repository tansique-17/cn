SHA 1

 

import java.security.MessageDigest;

import java.security.NoSuchAlgorithmException;

public class SHA1Example

{

    public static void main(String[] args)

    {

        String textToHash="HELLO";

        try

        {

            MessageDigest sha1Digest=MessageDigest.getInstance("SHA-1");

            sha1Digest.update(textToHash.getBytes());

            byte[] sha1Hash=sha1Digest.digest();

            StringBuilder hexStringBuilder=new StringBuilder();

            for (byte b:sha1Hash)

            {

                hexStringBuilder.append(String.format("%02x",b));

                

            }

            String sha1Hex=hexStringBuilder.toString();

            System.out.println("SHA-1 Hash:" + sha1Hex);

            

        }

        catch(NoSuchAlgorithmException e)

        {

            e.printStackTrace();

            

        }

        

    }

}

 

 

MD5

 

import java.security.MessageDigest;

import java.security.NoSuchAlgorithmException;

public class MD5Example {

public static void main(String[] args) {

String text = "Hello, World!";

try {

//Create MessageDigest instance for MD5

MessageDigest md = MessageDigest.getInstance("MD5") ;

// Add text bytes to digest

md.update (text .getBytes () );

// Get the hash's bytes

byte[] hashBytes = md.digest();

//Convert the bytes to hexadecimal format

StringBuilder hexString = new StringBuilder();

for (byte b : hashBytes) {

hexString. append (String.format ("%02x", b));

}

System.out.println("MD5 Hash of ' " + text + " ': " + hexString.toString());

} catch (NoSuchAlgorithmException e)

{

e.printStackTrace ();

 }

}

}

 

AES (RIJNDER ALGORITHM)

 

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
public class AESexample
{
public static void main(String[] args)
{
try
{
String secretKey = "zxcvbn0987654321";
String plainText = "PRAVALLIKA";

String encryptedText = encrypt(plainText,secretKey);
System.out.println("EncryptedText: "+encryptedText);

String decryptedText = decrypt(encryptedText,secretKey);
System.out.println("Decrypted Text: "+decryptedText);
}catch(Exception e)
{
e.printStackTrace();
   }
}
private static String encrypt(String plainText,String secretKey) throws Exception
{
Cipher cipher = Cipher.getInstance("AES");
SecretKeySpec keySpec= new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8),"AES");
cipher.init(Cipher. ENCRYPT_MODE, keySpec);
byte[] encryptedBytes = cipher.doFinal(plainText.getBytes (StandardCharsets.UTF_8));
return Base64.getEncoder().encodeToString(encryptedBytes);
}
private static String decrypt(String encryptedText,String secretKey) throws Exception
{
Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        return new String(cipher.doFinal(decodedBytes), StandardCharsets.UTF_8);
}
}

 

 

Diffihelman

 

import java.math.BigInteger;

import java.util.Random;

public class DiffieHellman 

{

public static void main(String[] args) 

{

BigInteger p = new BigInteger("23");  

BigInteger g = new BigInteger("5");

 

BigInteger aPrivate = generatePrivateKey(p); 

BigInteger aPublic = g.modPow(aPrivate, p);

 

BigInteger bPrivate = generatePrivateKey(p); 

BigInteger bPublic = g.modPow(bPrivate, p);

 

BigInteger sharedKeyAlice = bPublic.modPow(aPrivate, p);

BigInteger sharedKeyBob = aPublic.modPow(bPrivate, p);

if (sharedKeyAlice.equals(sharedKeyBob))

{

System.out.println("Key exchange successful!");

System.out.println("Shared Key: " + sharedKeyAlice);

} else {

System.out.println("Key exchange failed.");

 

}

 

}

private static BigInteger generatePrivateKey(BigInteger p) 

{

Random rand = new Random();

BigInteger maxLimit = p.subtract(BigInteger.ONE);

return new BigInteger(maxLimit.bitLength(), rand).mod(maxLimit).add(BigInteger.ONE);

}

}
