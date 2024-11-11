import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * Arguments
 * +Mode: -sign, -verify
 * +Hash Function: -sha1, -sha256
 * +File: file to sign/verify
 * Extra parameters
 * Sign Mode:
 * +KeyStoreFile with private key
 * +Password to access private key
 * Verify Mode:
 * +File with signature
 * +Certificate from signer
 * Output:
 * Sign Mode:
 * -File with signature only
 * Verify Mode:
 * -Validation on the signature
 */
public class Exc7 {
    public static void main(String[] args) {
        if(args.length < 5) throw new InvalidParameterException("Invalid number of parameters!");
        final String mode = args[0];
        final String hashFunction = args[1];
        final String inFileName = args[2];
        String hash;

        // Get Hash
        if(hashFunction.equalsIgnoreCase("-sha1")) hash = "SHA1withRSA";
        else if(hashFunction.equalsIgnoreCase("-sha256")) hash = "SHA256withRSA";
        else throw new IllegalStateException("Invalid hash function!");

        if(mode.equalsIgnoreCase("-sign")) {
            final String keyStore = args[3], password = args[4];
            try {
                sign(hash, inFileName, keyStore, password);
            } catch(CertificateException | NoSuchAlgorithmException | KeyStoreException |
                    UnrecoverableEntryException | SignatureException | InvalidKeyException e) {
                e.printStackTrace();
            }
        } else if(mode.equalsIgnoreCase("-verify")) {
            final String signatureFile = args[3], cert = args[4];
            boolean v = false;
            try {
                v = verify(hash, inFileName, signatureFile, cert);
            } catch(NoSuchAlgorithmException | InvalidKeyException | SignatureException | CertificateException e) {
                e.printStackTrace();
            }
            System.out.println("Signature " + (v ? "is" : "is not") + " valid!");
        } else throw new IllegalStateException("Specify sign mode: -sign or -verify");

    }

    /// Sign inFileName into an output file
    private static void sign(String hash, String inFileName, String ksFile, String password) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableEntryException, InvalidKeyException, SignatureException {
        KeyStore ks = readKeyStore(ksFile, password);
        Signature sign = getSignatureFromKS(ks, hash, password);
        if(sign == null) throw new IllegalStateException("No private key found");

        try(FileInputStream fis = new FileInputStream(inFileName); FileOutputStream fos = new FileOutputStream("Signed" + inFileName)) {
            byte[] input = new byte[1024];
            int currBytes;
            while((currBytes = fis.read(input)) > 0) {
                sign.update(input, 0, currBytes);
            }
            byte[] signBytes = sign.sign();
            fos.write(signBytes);
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    /// Verify Signature
    private static boolean verify(String hash, String inFileName, String signatureFile, String certificate) throws NoSuchAlgorithmException, InvalidKeyException, CertificateException, SignatureException {
        byte[] inputSign = new byte[(int) new File(signatureFile).length()];
        try(FileInputStream fis = new FileInputStream(signatureFile)) {
            fis.read(inputSign);
        } catch(IOException e) {
            e.printStackTrace();
        }

        // Get certificate
        X509Certificate cert = getCertificate(certificate);

        // Get public key from certificate
        PublicKey pk = cert.getPublicKey();

        // Get Signature object to sign
        Signature sign = Signature.getInstance(hash);
        sign.initVerify(pk);

        // Sign input file
        try(FileInputStream fis = new FileInputStream(inFileName)) {
            byte[] inputBytes = new byte[1024];
            int currBytes;
            while((currBytes = fis.read(inputBytes)) > 0) sign.update(inputBytes, 0, currBytes);
        } catch(IOException e) {
            e.printStackTrace();
        }
        // Verify signature
        return sign.verify(inputSign);
    }

    /// Load KeyStore from file
    private static KeyStore readKeyStore(String ksFile, String password) throws CertificateException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try(FileInputStream fis = new FileInputStream(ksFile)) {
            ks.load(fis, password.toCharArray());
        } catch(IOException e) {
            e.printStackTrace();
        }
        return ks;
    }

    /// Get Signature object to sign and check if cert has a private key
    private static Signature getSignatureFromKS(KeyStore ks, String hash, String password) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableEntryException, InvalidKeyException {
        Signature sign = Signature.getInstance(hash);
        Enumeration<String> alias = ks.aliases();
        String privateKey;
        while(alias.hasMoreElements()) {
            privateKey = alias.nextElement();
            if(ks.isKeyEntry(privateKey)) {
                KeyStore.PasswordProtection passProt = new KeyStore.PasswordProtection(password.toCharArray());
                KeyStore.PrivateKeyEntry pkE = (KeyStore.PrivateKeyEntry) ks.getEntry(privateKey, passProt);
                PrivateKey pk = pkE.getPrivateKey();

                sign.initSign(pk);
                return sign;
            }
        }
        return null;
    }

    /// Load Certificate from file name
    private static X509Certificate getCertificate(String nameCert) throws CertificateException {
        try(FileInputStream in = new FileInputStream(nameCert)) {
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            return (X509Certificate) f.generateCertificate(in);
        } catch(IOException e) {
            e.printStackTrace();
        }
        throw new CertificateException("This Certificate is invalid!");
    }
}
