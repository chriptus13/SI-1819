import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Arguments
 * +Mode: -cipher, -decipher
 * +File with 8 byte key
 * +Input File
 * +Output File
 */
public class Exc6 {
    private static final String CIPHER = "DES/CBC/PKCS5Padding", HMAC = "HmacSHA1";
    private static final int TAG_SIZE = 20, DES_BLOCK_SIZE = 8, IV_SIZE = 8, INPUT_BLOCK_SIZE = 1024;

    public static void main(String[] args) {
        if(args.length < 4) throw new InvalidParameterException("Invalid number of parameters!");

        final String encryptionMode = args[0], keyFileName = args[1],
                inFileName = args[2], outFileName = args[3];

        try {
            // Get key
            byte[] keyBytes = new byte[8];
            try(FileInputStream in = new FileInputStream(keyFileName)) {
                in.read(keyBytes);
            }

            final SecretKeyFactory cipherKeyFactory = SecretKeyFactory.getInstance("DES");
            final SecretKey key = cipherKeyFactory.translateKey(cipherKeyFactory.generateSecret(new DESKeySpec(keyBytes)));

            // Cipher/Decipher
            final Cipher cipher = Cipher.getInstance(CIPHER);
            final Mac mac = Mac.getInstance(HMAC);

            if(encryptionMode.equalsIgnoreCase("-cipher")) cipher(cipher, mac, key, inFileName, outFileName);
            else if(encryptionMode.equalsIgnoreCase("-decipher")) decipher(cipher, mac, key, inFileName, outFileName);
            else throw new IllegalStateException("Specify encryption mode: -cipher or -decipher");

        } catch(InvalidKeyException | IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private static void cipher(Cipher cipher, Mac mac, SecretKey key, String inFileName, String outFileName) throws InvalidKeyException, InvalidAlgorithmParameterException {
        // Calculate cipher size with padding
        File inFile = new File(inFileName);
        long cipherSize = (long) (Math.ceil(inFile.length() / (DES_BLOCK_SIZE * 1.0)) * DES_BLOCK_SIZE);

        // Generate IV
        SecureRandom sr = new SecureRandom();
        byte[] iv = new byte[IV_SIZE];
        sr.nextBytes(iv);
        final IvParameterSpec ivps = new IvParameterSpec(iv);

        // Initialize cipher and mac
        cipher.init(Cipher.ENCRYPT_MODE, key, ivps);
        mac.init(key);

        try(FileInputStream fis = new FileInputStream(inFile); DataOutputStream ps = new DataOutputStream(new FileOutputStream(outFileName))) {
            // Write Cipher Size (8 Bytes)
            ps.writeLong(cipherSize);

            // Write IV (8 Bytes)
            ps.write(iv);
            byte[] input = new byte[INPUT_BLOCK_SIZE];
            int currBytes;

            // Write Cipher and generate Tag (cipherSize Bytes)
            while((currBytes = fis.read(input)) > 0) {
                byte[] blockCiphered = cipher.update(input, 0, currBytes);
                if(blockCiphered != null) {
                    mac.update(blockCiphered);
                    ps.write(blockCiphered);
                }
            }
            // Do finals
            byte[] lastBlock = cipher.doFinal();
            if(lastBlock != null) {
                ps.write(lastBlock);
                mac.update(lastBlock);
            }
            byte[] tag = mac.doFinal();

            // Write Tag
            ps.write(tag);
        } catch(IOException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    private static void decipher(Cipher cipher, Mac mac, SecretKey key, String inFileName, String outFileName) throws InvalidKeyException, InvalidAlgorithmParameterException {
        try(DataInputStream in = new DataInputStream(new FileInputStream(inFileName)); PrintStream ps = new PrintStream(outFileName)) {
            // Read cipherSize (8 Bytes)
            long bytesToRead = in.readLong();

            // Read IV (8 Bytes)
            byte[] iv = new byte[IV_SIZE];
            in.read(iv);
            IvParameterSpec ivps = new IvParameterSpec(iv);

            // Initialize cipher and mac
            cipher.init(Cipher.DECRYPT_MODE, key, ivps);
            mac.init(key);

            // Read cipher: decipher it and generate Tag
            int currBytes;
            do {
                byte[] input = bytesToRead >= INPUT_BLOCK_SIZE ? new byte[INPUT_BLOCK_SIZE] : new byte[(int) bytesToRead];
                currBytes = in.read(input);
                if(currBytes > 0) {
                    bytesToRead -= currBytes;
                    mac.update(input, 0, currBytes);
                    byte[] decipheredBytes = cipher.update(input);
                    if(decipheredBytes != null) ps.write(decipheredBytes);
                } else break;
            } while(bytesToRead > 0);

            // Do finals
            byte[] lastBlock = cipher.doFinal();
            if(lastBlock != null) ps.write(lastBlock);
            byte[] currTag = mac.doFinal();

            // Read Tag (last 20 Bytes)
            byte[] tag = new byte[TAG_SIZE];
            in.read(tag);

            // Check Authenticity
            boolean authentic = Arrays.equals(tag, currTag);
            System.out.println("This message " + (authentic ? "is" : "is not") + " authentic!");
        } catch(IOException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }
}
