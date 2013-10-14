import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;


public class ReadIntro 
{
	public static void main(String args[]) throws OperatorCreationException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException, CertException
	{
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA","BC");
        keyGen.initialize(512);
        
        KeyPair rsaKey = keyGen.generateKeyPair();
        PrivateKey privateKey = rsaKey.getPrivate();
        PublicKey publicKey = rsaKey.getPublic();
        
	    ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withDSA").setProvider("BC").build(privateKey);
		AlgorithmIdentifier rsaEncryption = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, null); 
		SubjectPublicKeyInfo subPubKeyInfo = new SubjectPublicKeyInfo(rsaEncryption, publicKey.getEncoded());
	        
	    Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
	    Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);
	   
	    X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(
	              new X500Name("CN=Test"), 
	              BigInteger.ONE, 
	              startDate, endDate, 
	              new X500Name("CN=Test"), 
	              subPubKeyInfo);
	        
	   X509CertificateHolder certHolder = v1CertGen.build(sigGen);
	   CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

	   gen.addSignerInfoGenerator(
	            new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
	                .build(sigGen, certHolder));

	   ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder()
       .setProvider("BC").build(publicKey);

	   
   if (!certHolder.isSignatureValid(contentVerifierProvider))
   {
       System.err.println("signature invalid");
   }
	   System.out.println(certHolder.isSignatureValid(contentVerifierProvider));
	   
	}

}
