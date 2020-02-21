import java.io.Console;  
import java.io.PrintWriter;
import java.io.IOException;
import java.io.FileWriter;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Mac;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.*;
import java.lang.String;

public class generator 
{
	private static final SecureRandom random = new SecureRandom();

	private static String bytesToHex(byte[] hashInBytes) 
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hashInBytes.length; i++) 
        {
            sb.append(Integer.toString((hashInBytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }

	public static void generateKey()
	{
		try
        {
            //generate key
            String algorithm = "HMACSHA256";
            KeyGenerator kgen = KeyGenerator.getInstance(algorithm);
            SecretKey skey = kgen.generateKey();

            //save the key in a file 
            String keyFile = "key";
            FileOutputStream out = new FileOutputStream(keyFile);
            byte[] key = skey.getEncoded();
            out.write(key);
            out.close();
        }
        catch(Exception except)
        {
            except.printStackTrace(); 
        }
	}

    public static String Hash(String password, String salt)
    {
		try
        {
            //Generate Key
            //generateKey();

        	String passSalt;
			passSalt = password + salt;

            // decode encoded string
            Path fileLocation = Paths.get("key"); 
            byte[] key = Files.readAllBytes(fileLocation);

            // rebuild key using SecretKeySpec
            SecretKey sk = new SecretKeySpec(key, "HMACSHA256");

            Mac mac = Mac.getInstance("HMACSHA256");
            mac.init(sk);
            return bytesToHex(mac.doFinal(passSalt.getBytes()));
            
        }

        catch(Exception e)
        {
            System.out.println("Error while hashing: " + e.toString());
        }

        return null;
    }
	public static void main(String[] args)
	{
		//take in user and pass from command line
		String username = args[0];
		String password = args[1];

		//generate 32 bit salt
		byte[] salt = new byte[4];
    	random.nextBytes(salt);
    	String saltString = new String(salt);

    	//hash password and salt 
    	String hashedPassSalt = Hash(password, saltString);

    	//store [username, salt, H(password||salt)] in file

    	//clear file
    	File file = new File("pwd.txt"); 
	    if (file.exists()) 
	    	{   
	    		//delete if exists    
	    		file.delete(); 
	    	}

	    //write
	    try (FileWriter f = new FileWriter("pwd.txt", true); 
			BufferedWriter b = new BufferedWriter(f); 
			PrintWriter p = new PrintWriter(b);) 
		{ 
			p.println(username);
			p.println(saltString); 
			p.println(hashedPassSalt);
		} 
		catch (IOException i) 
		{ 
			i.printStackTrace(); 
		} 
	}	   
}