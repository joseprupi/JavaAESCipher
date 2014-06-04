package JavaAESCipher;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author rupi
 */
public class Test {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            AESCipher aes = new AESCipher();
            
            if("E".equals(args[0])){
                
                aes.generateKey(256);
            
                aes.saveKey("key.txt");
            
                aes.encrypt(aes.ECB_PKCS5, "in.txt", "out1.txt");
                aes.encrypt(aes.ECB, "in.txt", "out2.txt");
                aes.encrypt(aes.CCB_PKCS5, "in.txt", "out3.txt");
                aes.encrypt(aes.CCB, "in.txt", "out4.txt");
                
                aes.getKeyFromPassword("pepo");
            
                aes.encrypt(aes.ECB_PKCS5, "in.txt", "out1_pass.txt");
                aes.encrypt(aes.ECB, "in.txt", "out2_pass.txt");
                aes.encrypt(aes.CCB_PKCS5, "in.txt", "out3_pass.txt");
                aes.encrypt(aes.CCB, "in.txt", "out4_pass.txt");                                
                
            }else if("D".equals(args[0])){
                
                aes.readKey("key.txt");
            
                aes.decrypt(aes.ECB_PKCS5, "out1.txt", "res1.txt");
                aes.decrypt(aes.ECB, "out2.txt", "res2.txt");
                aes.decrypt(aes.CCB_PKCS5, "out3.txt", "res3.txt");
                aes.decrypt(aes.CCB, "out4.txt", "res4.txt");



                aes.getKeyFromPassword("pepo");

                aes.decrypt(aes.ECB_PKCS5, "out1_pass.txt", "res1_pass.txt");
                aes.decrypt(aes.ECB, "out2_pass.txt", "res2_pass.txt");
                aes.decrypt(aes.CCB_PKCS5, "out3_pass.txt", "res3_pass.txt");
                aes.decrypt(aes.CCB, "out4_pass.txt", "res4_pass.txt");
                
            }                                    
        
        } catch (Exception ex) {
            Logger.getLogger(Practica1.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
