127

#include <stdio.h> 
#include<stdlib.h> 
void main() 
{ 
char str[]="Hello World"; 
char str1[11]; 
char str2[11]=str[]; 
int i,len; 
len = strlen(str); 
for(i=0;i<len;i++) 
{ 
str1[i] = str[i]&127; 
printf("%c",str1[i]); 
} 
printf("\n"); 
for(i=0;i<len;i++) 
{ 
str3[i] = str2[i]^127; 
printf("%c",str3[i]); 
} 
printf("\n"); 
}

BLOWFISH 

import javax.crypto.Cipher; 
import javax.crypto.KeyGenerator; 
import javax.crypto.SecretKey; 
import javax.swing.JOptionPane; 
public class BlowFishCipher { 
   public static void main(String[] args) throws Exception { 
KeyGeneratorkeygenerator = KeyGenerator.getInstance("Blowfish"); 
cipher = Cipher.getInstance("Blowfish"); 
cipher.init(Cipher.ENCRYPT_MODE, secretkey); 
String inputText = JOptionPane.showInputDialog("Input your message: "); 
byte[] encrypted = cipher.doFinal(inputText.getBytes()); 
cipher.init(Cipher.DECRYPT_MODE, secretkey); 
byte[] decrypted = cipher.doFinal(encrypted); 
JOptionPane.showMessageDialog(JOptionPane.getRootFrame(), 
"\nEncrypted text: " + new String(encrypted) + "\n" + 
"\nDecrypted text: " + new String(decrypted)); 
System.exit(0); 
} }

