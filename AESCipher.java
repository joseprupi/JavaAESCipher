/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package JavaAESCipher;

/**
 *
 * @author rupi
 */

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCipher{
    
    private final String KEY_ALGO = "AES";
    private final String PBE_ALGO = "PBKDF2WithHmacSHA1";
    
    //Modes de xifrat
    public final String ECB_PKCS5 = "AES/ECB/PKCS5Padding";
    public final String ECB = "AES/ECB/NoPadding";
    public final String CCB_PKCS5 = "AES/CBC/PKCS5Padding";
    public final String CCB = "AES/CBC/NoPadding";
            
    //Clau, salt i vector inicialització
    private SecretKey key;
    private final byte[] salt = "saltytasty".getBytes();
    //private byte[] ivbytes = new byte[16];
    
    private byte[] ivbytes = new byte[] {(byte)'l', (byte)'b', (byte)'c', (byte)'d', 
        (byte)'e', (byte)'f', (byte)'g', (byte)'h', (byte)'i', (byte)'j', 
        (byte)'k', (byte)'l', (byte)'m', (byte)'n', (byte)'o', (byte)'p'};

    public void generateKey(int size) throws Exception{
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom random = new SecureRandom();
        keyGen.init(size, random);
        key = keyGen.generateKey();
    }
    
    public void getKeyFromPassword(String password) throws Exception{
        
        if("".equals(password)){
            throw(new Exception("El password no pot estar vuit"));
        }

        SecretKeyFactory factory = SecretKeyFactory.getInstance(this.PBE_ALGO);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), this.KEY_ALGO);
        
    }

    public void encrypt(String mode, String fname, String fout) throws Exception{
        
        if(key == null){
            throw(new Exception("Es necessita una clau"));
        }
        
        Cipher encipher;
        CipherInputStream cis; 
        
        InputStream in = new FileInputStream(fname);
        OutputStream out = new FileOutputStream(fout);
        
        if(!mode.equals(ECB_PKCS5) && !mode.equals(ECB) && 
                !mode.equals(CCB_PKCS5) && !mode.equals(CCB)){
            throw(new Exception("Mida incorrecta"));
        }
        
        encipher = Cipher.getInstance(mode);
        
        if(mode.equals(ECB_PKCS5) || mode.equals(ECB)){
            encipher.init(Cipher.ENCRYPT_MODE, key);   
        }
        
        if(mode.equals(CCB_PKCS5) || mode.equals(CCB)){
            //new SecureRandom().nextBytes(ivbytes);
            IvParameterSpec iv = new IvParameterSpec(ivbytes);
            encipher.init(Cipher.ENCRYPT_MODE, key, iv);
        }
        
        cis = new CipherInputStream(in, encipher);
        
        isToOs(cis, out);

    }

    public void decrypt(String mode, String fname, String fout) throws Exception{
        
        if(key == null){
            throw(new Exception("Es necessita una clau"));
        }
        
        Cipher encipher;
        CipherOutputStream cos; 
        
        InputStream in = new FileInputStream(fname);
        OutputStream out = new FileOutputStream(fout);
        
        if(!mode.equals(ECB_PKCS5) && !mode.equals(ECB) && 
                !mode.equals(CCB_PKCS5) && !mode.equals(CCB)){
            System.out.println("Mida incorrecta");
            return;
        }
        
        encipher = Cipher.getInstance(mode);
        
        if(mode.equals(ECB_PKCS5) || mode.equals(ECB)){
            encipher.init(Cipher.DECRYPT_MODE, key);   
        }
        
        if(mode.equals(CCB_PKCS5) || mode.equals(CCB)){
            IvParameterSpec iv = new IvParameterSpec(ivbytes);
            encipher.init(Cipher.DECRYPT_MODE, key, iv);
        }
        
        cos = new CipherOutputStream(out, encipher);
        
        isToOs(in, cos);
    
    }

    public void saveKey(String fname) throws Exception{
        OutputStream out = new FileOutputStream(fname);
        out.write(key.getEncoded());
        out.close();
    }

    public void readKey(String fname) throws Exception{
        RandomAccessFile f = new RandomAccessFile(fname, "r");
        byte[] b = new byte[(int)f.length()];
        f.read(b);
        key = new SecretKeySpec(b, 0, b.length, this.KEY_ALGO);
        f.close();
    }

    
    public void isToOs(InputStream is, OutputStream os) throws IOException{
    
        byte[] buf = new byte[100];
        int numbytes;
        
        while((numbytes = is.read(buf)) != -1){
            os.write(buf, 0, numbytes);
            os.flush();
        }
        
        is.close();
        os.close();
        
    }
        
}