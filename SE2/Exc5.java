import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.security.cert.X509Certificate;
import java.io.IOException;
import java.security.InvalidParameterException;
import java.security.Principal;
import java.util.Arrays;
import java.util.stream.Collectors;

public class Exc5 {
    public static void main(String[] args) {
        if(args.length < 1) throw new InvalidParameterException("Invalid number of parameters!");
        final String domain = args[0];
        System.out.println(domain);

        SSLSocketFactory sslFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try {
            SSLSocket socket = (SSLSocket) sslFactory.createSocket(domain, 443);
            SSLSession session = socket.getSession();
            String[] supportedProtocols = socket.getSupportedProtocols();
            X509Certificate[] chain = session.getPeerCertificateChain();
            if(chain == null) System.out.println("No certificates for current domain!");
            else {
                X509Certificate minDate = Arrays.stream(chain).min((c1, c2) -> (int) (c2.getNotAfter().getTime() - c1.getNotAfter().getTime())).get();
                System.out.println("-> Certificate chain: \n\t" + Arrays.stream(chain).map(X509Certificate::getSubjectDN).map(Principal::toString).collect(Collectors.joining("\n\t")));
                System.out.println("-> Certificate with minimum expiration date: " + minDate.getSubjectDN());
                System.out.println("\t -> Date:" + minDate.getNotAfter());
            }
            System.out.println("-> SSL and TLS supported versions: ");
            Arrays.stream(supportedProtocols).filter(pt -> !pt.equals("SSLv2Hello")).forEach(pt -> {
                try {
                    SSLSocket skt = (SSLSocket) sslFactory.createSocket(domain, 443);
                    skt.setEnabledProtocols(new String[]{pt});
                    skt.startHandshake();
                    System.out.println('\t' + pt);
                } catch(IOException | IllegalArgumentException ignored) {
                    System.out.println('\t' + pt + "[NOT SUPPORTED]");
                }
            });
        } catch(IOException e) {
            e.printStackTrace();
        }
    }
}
