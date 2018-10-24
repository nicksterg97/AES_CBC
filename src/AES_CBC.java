
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import sun.misc.BASE64Encoder;

public class AES_CBC {

    private byte[][] cypherTextBlocks;

    public static void main(String[] args) throws IOException {

        String part1_URL = "http://crypto-class.appspot.com/po?er=";
        String cryptoURL = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4";
        byte[] cypherText = hexToBytes(cryptoURL); //to kanei se 64 Bytes

        AES_CBC a = new AES_CBC();
        a.seperateBlock(cypherText); //kaloume tin sinartisi pou dimiourgei 4 blocks apo 16Bytes to cypherText
        System.out.println(cypherText.length);

        String clearText = a.decrypt(part1_URL, cryptoURL, cypherText);
        byte[] clearBytes=clearText.getBytes();
        System.out.println("Final plain text is : " + clearText);

        System.out.println("Encrypted plain text is : " + a.encrypt(clearBytes));

    }

    public AES_CBC() {
        this.cypherTextBlocks = new byte[4][];
    }

    public String decrypt(String part1_URL, String cryptoURL, byte[] cypherText) {
        byte[] plainText = new byte[cypherText.length - 16]; //pinakas pou tha exei megethos oso to cypherText se Bytes ektos apo to teleutaio block gi auto kai to -16
        int cypherCounter = 64; //to megethos tou cypherText se Bytes

        for (int i = cypherTextBlocks.length - 1; i > 0; i--) { //eksetazoume ola ta block ektos apo to teleutaio 

            System.out.println("Current Block:  " + i);
            byte[] prevBlock = cypherTextBlocks[i - 1]; //anafora pou deixnei sto proigoumeno block apo auto pou eksetazoume
            byte[] currentCypherText = Arrays.copyOf(cypherText, cypherCounter); //pinakas pou periexei to trexwn cypherText se bytes pou eksetazoume

            for (int pad = 1; pad <= 16; pad++) { //diatrexei ola ta byte tou cuurrent block
                System.out.println("\nCurrent Byte:  " + pad);

                for (int k = 1; k < pad; k++) { //pame sto proigoumeno block gia na kanoume tin alloiwsi
                    int cypherByte = currentCypherText.length - 16 - k; //einai to byte olou tou cypherText pou eksetazw tou proigoumenoublock
                    //apo ton tupo C1 ^ P ^ C1' 
                    currentCypherText[cypherByte] = (byte) (prevBlock[16 - k] ^ plainText[cypherByte] ^ pad); //se auto to simeio kanoume tin alloiwsi 
                }

                for (int guess = 0; guess < 128; guess++) {
                    try {
                        //dokimazoume tous 256 diaforetikous sundiasmoys
                        if (guess == 1 && pad == 1) {
                            continue;
                        }
                        //PLAINTEXT
                        currentCypherText[currentCypherText.length - 16 - pad] = (byte) (prevBlock[16 - pad] ^ guess ^ pad); // apo tin sxesi stis diafanies P= C1 ^ C1' ^ 0x01

                        String testURL = BytetoHex(currentCypherText);
                        int serverCode = hitURL(part1_URL, testURL); //o kwdikos pou epistrefei o server 

                        if (serverCode == 200 || serverCode == 404) { //an o server epistrepei 200 i 404 exei
                            plainText[i * 16 - pad] = (byte) guess;
                            System.out.println("Correct guess:" + guess);
                            break;
                        }
                    } catch (IOException ex) {
                        Logger.getLogger(AES_CBC.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
            cypherCounter = cypherCounter - 16;//metritis pou ksekinaei tin prwti fora apo 64 diladi oso einai to mikos twn bytes tou cypherText kathe fora eksetazoume 16Bytes 
        }
        return (new String(plainText));

    }

    public static byte[] encrypt(byte[] cypher) {
        SecureRandom secureRandom;
        Cipher cipher;
        Mac mac;
        byte[] iv = new byte[16];
        byte[] aesKey = new byte[32];
        byte[] macKey = new byte[32];

        byte[] ciphertext = null;
        byte[] macBytes;
        try {

            secureRandom = new SecureRandom();
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            mac = Mac.getInstance("HmacSHA512");

            KeyGenerator keygen = KeyGenerator.getInstance("AES"); 
            keygen.init(256); 
            byte[] key = keygen.generateKey().getEncoded();
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

            secureRandom.nextBytes(iv);
            secureRandom.nextBytes(aesKey);
            secureRandom.nextBytes(macKey);

            try {
                SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey, "AES");
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
                ciphertext = cipher.doFinal(cypher);

                mac.init(skeySpec);
                mac.update(iv);
                macBytes = mac.doFinal(ciphertext);
            } catch (IllegalBlockSizeException | BadPaddingException
                    | InvalidAlgorithmParameterException | InvalidKeyException e) {

                System.out.println("error");
            }

        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {

            System.out.println("error");
        }
        return ciphertext;

    }

    public int hitURL(String part1_URL, String cryptoURL) throws IOException {
        //System.out.println("Crypto is : "+cryptoURL);
        String fullURL = part1_URL + cryptoURL;
        URL url = new URL(fullURL);

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        int serverResponseCode = conn.getResponseCode();
        conn.disconnect();
        return serverResponseCode;
    }

    public static byte[] hexToBytes(String cypher) {
        HexBinaryAdapter adapter = new HexBinaryAdapter();
        byte[] bytes = adapter.unmarshal(cypher);
        return bytes;
    }

    public String BytetoHex(byte[] byteArray) {
        StringBuilder sb = new StringBuilder(byteArray.length * 2);
        for (byte b : byteArray) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public void seperateBlock(byte[] cypherText) {

        int counterStart = 0; //deixnei stin arxi tou kathe block kai ksekinaei apo 0 gia to prwto block
        int counterEnd = 16; //deixnei sto telos kathe block kai ksekinaei apo 16 gia to prwto block
        for (int i = 0; i < cypherTextBlocks.length; i++) {

            cypherTextBlocks[i] = Arrays.copyOfRange(cypherText, counterStart, counterEnd);
            //auksanoume tous metrites gia na deiksoun sto epomeno block
            counterStart = counterStart + 16;
            counterEnd = counterEnd + 16;
        }
        System.out.println(Arrays.toString(cypherTextBlocks));

    }

}
