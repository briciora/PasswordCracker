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
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.ArrayList;

public class cracker3
{
	public static final char[] possibilites = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();
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

	public static String Hash(String password, String saltString)
    {
		try
        {
        	String passSalt;
			passSalt = password + saltString;

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

	public static Integer combinations(String username, String salt, String hashedPassSalt)
	{
		int trialsCount = 0;
		char current;
		String test;
		String hashedTest;

		for(int i= 0; i < possibilites.length; i++)
		{
			current = possibilites[i];

			for(int ii= 0; ii < possibilites.length; ii++)
			{
				test = "" + current + possibilites[ii];

				trialsCount++;

				hashedTest = Hash(test, salt);

				if(hashedTest.equals(hashedPassSalt))
				{
					System.out.println(hashedTest);
					return trialsCount;
				}
			}
		}

		for(int i= 0; i < possibilites.length; i++)
		{
			current = possibilites[i];

			for(int ii= 0; ii < possibilites.length; ii++)
			{
				for(int iii= 0; iii < possibilites.length; iii++)
				{
					test = "" + current + possibilites[ii] + possibilites[iii];

					trialsCount++;

					hashedTest = Hash(test, salt);

					if(hashedTest.equals(hashedPassSalt))
					{
						System.out.println(hashedTest);
						return trialsCount;
					}
				}
			}
		}

		for(int i= 0; i < possibilites.length; i++)
		{
			current = possibilites[i];

			for(int ii= 0; ii < possibilites.length; ii++)
			{
				for(int iii= 0; iii < possibilites.length; iii++)
				{
					for(int iiii= 0; iiii < possibilites.length; iiii++)
					{
						test = "" + current + possibilites[ii] + possibilites[iii] + possibilites[iiii];

						trialsCount++;

						hashedTest = Hash(test, salt);

						if(hashedTest.equals(hashedPassSalt))
						{
							System.out.println(hashedTest);
							return trialsCount;
						}
					}
				}
			}
		}

		for(int i= 0; i < possibilites.length; i++)
		{
			current = possibilites[i];

			for(int ii= 0; ii < possibilites.length; ii++)
			{
				for(int iii= 0; iii < possibilites.length; iii++)
				{
					for(int iiii= 0; iiii < possibilites.length; iiii++)
					{
						for(int iiiii= 0; iiiii < possibilites.length; iiiii++)
						{
							test = "" + current + possibilites[ii] + possibilites[iii] + possibilites[iiii] + possibilites[iiiii];

							trialsCount++;

							hashedTest = Hash(test, salt);

							if(hashedTest.equals(hashedPassSalt))
							{
								System.out.println(hashedTest);
								return trialsCount;
							}
						}
					}
				}
			}
		}
		return -1;
	}

	public static void main(String[] args)
	{
		try
		{
			//reads message from pwd.txt

			String fileName = "pwd.txt";
			File file = new File(fileName);
			FileReader fr = new FileReader(file);
			BufferedReader br = new BufferedReader(fr);
			
            String readLine;
            ArrayList<String> pwdData = new ArrayList<String>();
            int i = 0; 
            while ((readLine = br.readLine()) != null) 
            {
                pwdData.add(readLine);
                i++;
            }

            String username = pwdData.get(0);
            String saltString = pwdData.get(1);
            String hashedPassSalt = pwdData.get(2);

            //salt string --> bytes
            byte[] salt = saltString.getBytes();

            //crack
            double startTime = System.currentTimeMillis();
            Integer trials = combinations(username, saltString, hashedPassSalt);
            double endTime = System.currentTimeMillis();
            double time = (endTime - startTime) / 1000;

			//print number of trials, and time
	        System.out.println("The password has been cracked!");
	        System.out.println("It took " + trials + " trials and " + time + " seconds." ); 
    	}
    	catch(IOException i)
    	{
    		i.printStackTrace(); 
    	}
    }
}