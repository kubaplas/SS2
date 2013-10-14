import java.io.File;
import java.io.FileWriter;
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
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;



public class Intro 
{
	
	public static String bytesToHex(byte[] bytes) {
	    final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	    char[] hexChars = new char[bytes.length * 2];
	    int v;
	    for ( int j = 0; j < bytes.length; j++ ) {
	        v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	public static void main(String args[]) throws NoSuchAlgorithmException, OperatorCreationException, IOException, InvalidKeySpecException, InvalidKeyException, SignatureException, CertException, NoSuchProviderException
	{
		Security.addProvider(new BouncyCastleProvider());
		Random rand = new Random();
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        
        KeyPair rsaKey = keyGen.generateKeyPair();
        PrivateKey privateKey = rsaKey.getPrivate();
        PublicKey publicKey = rsaKey.getPublic();
        
        KeyPair rsaKey1 = keyGen.generateKeyPair();
        PrivateKey privateKey1 = rsaKey1.getPrivate();
        PublicKey publicKey1 = rsaKey1.getPublic();
		
//		RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
//		generator.init(new RSAKeyGenerationParameters
//		    (
//		        new BigInteger("10001", 16),//publicExponent
//		        SecureRandom.getInstance("SHA1PRNG"),//prng
//		        1024,//strength
//		        80//certainty
//		    ));
//
//		AsymmetricCipherKeyPair keys = generator.generateKeyPair();
        
		
		
		ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);
//		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
//        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
//
//        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKey);
		
		
		AlgorithmIdentifier rsaEncryption = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, null); 
		SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(rsaEncryption, publicKey.getEncoded());
		Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
		Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);
		X500NameBuilder nameBuilder = new X500NameBuilder();
		nameBuilder.addRDN(BCStyle.CN, "testCA");
		nameBuilder.addRDN(BCStyle.C, "UK");
		nameBuilder.addRDN(BCStyle.E,"qwerasd@gmail.com");
		nameBuilder.addRDN(BCStyle.GENDER,"M");
		X500Name name1 = nameBuilder.build();
		X509v1CertificateBuilder buildCert = new X509v1CertificateBuilder(name1, BigInteger.valueOf(rand.nextLong()), startDate, endDate, name1, publicKeyInfo);
		X509CertificateHolder CAcert = buildCert.build(sigGen);
		 CMSSignedDataGenerator gen = new CMSSignedDataGenerator();   
		gen.addSignerInfoGenerator(
		            new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
		                .build(sigGen, CAcert));

		ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder()
	       .setProvider("BC").build(publicKey);
		
		System.out.println(CAcert.isSignatureValid(contentVerifierProvider));
		
    	PEMWriter pemWriter = new PEMWriter(new FileWriter(new File("D:\\certs\\CAcert.crt")));
    	pemWriter.writeObject(CAcert);
    	pemWriter.flush();
    	
    	pemWriter = new PEMWriter(new FileWriter(new File("D:\\certs\\privateCA.pem")));
    	pemWriter.writeObject(privateKey);
    	pemWriter.flush();
    	
    	pemWriter = new PEMWriter(new FileWriter(new File("D:\\certs\\publicCA.pem")));
    	pemWriter.writeObject(publicKey);
    	pemWriter.flush();
    	
    	
		rsaEncryption = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, null); 
		publicKeyInfo = new SubjectPublicKeyInfo(rsaEncryption, publicKey1.getEncoded());
		startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
		endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);
		nameBuilder = new X500NameBuilder();
		nameBuilder.addRDN(BCStyle.CN, "testZiom");
		nameBuilder.addRDN(BCStyle.C, "UK");
		nameBuilder.addRDN(BCStyle.E,"qwerasd@gmail.com");
		nameBuilder.addRDN(BCStyle.GENDER,"M");
		X500Name name = nameBuilder.build();
		buildCert = new X509v1CertificateBuilder(name1, BigInteger.valueOf(rand.nextLong()), startDate, endDate, name, publicKeyInfo);
		X509CertificateHolder ZIOMcert = buildCert.build(sigGen);
		gen = new CMSSignedDataGenerator();
		gen.addSignerInfoGenerator(
	            new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
	                .build(sigGen, ZIOMcert));
		System.out.println(ZIOMcert.isSignatureValid(contentVerifierProvider));
    	
		
		pemWriter = new PEMWriter(new FileWriter(new File("D:\\certs\\ZIOMcert.crt")));
    	pemWriter.writeObject(ZIOMcert);
    	pemWriter.flush();
    	
    	pemWriter = new PEMWriter(new FileWriter(new File("D:\\certs\\privateZIOM.pem")));
    	pemWriter.writeObject(publicKey1);
    	pemWriter.flush();
    	
    	pemWriter = new PEMWriter(new FileWriter(new File("D:\\certs\\publicZIOM.pem")));
    	pemWriter.writeObject(privateKey1);
    	pemWriter.flush();
    	pemWriter.close();
//
//    	X509v2AttributeCertificateBuilder buildAttrCert = new X509v2AttributeCertificateBuilder(new AttributeCertificateHolder(ZIOMcert), new AttributeCertificateIssuer(CAcert.getIssuer()), BigInteger.valueOf(rand.nextLong()), startDate, endDate);
//    	buildAttrCert.addAttribute(new ASN1ObjectIdentifier("2.5.4.72"), new DERPrintableString("admin:sys"));
//    	X509AttributeCertificateHolder attrCertificate = buildAttrCert.build(sigGen);
//    	System.out.println(attrCertificate.isSignatureValid(contentVerifierProvider));
    	
//    	PemReader pemReaderCerts = new PemReader(new FileReader(new File("D:\\certs\\CAcert.crt")));
//    	X509CertificateHolder CaCert = new X509CertificateHolder(pemReaderCerts.readPemObject().getContent());
//    	System.out.println(CaCert.getIssuer().toString());
//
//    	pemReaderCerts = new PemReader(new FileReader(new File("D:\\certs\\CaPubKey.pem")));
//    	RSAKeyParameters pk = (RSAKeyParameters) PublicKeyFactory.createKey(pemReaderCerts.readPemObject().getContent());
//    	RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(pk.getModulus(), pk.getExponent());
//    	KeyFactory kf = KeyFactory.getInstance("RSA");
//    	PublicKey rsaPub = kf.generatePublic(rsaSpec);
//    	System.out.println(rsaPub.toString());
//    	
//
//    	SubjectPublicKeyInfo pubKeyCa = CaCert.getSubjectPublicKeyInfo();
//    	RSAKeyParameters pk1 = (RSAKeyParameters) PublicKeyFactory.createKey(pubKeyCa.getPublicKeyData().getBytes());
//    	RSAPublicKeySpec rsaSpec1 = new RSAPublicKeySpec(pk1.getModulus(), pk1.getExponent());
//    	KeyFactory kf1 = KeyFactory.getInstance("RSA");
//    	PublicKey rsaPub1 = kf1.generatePublic(rsaSpec1);
//    	System.out.println(rsaPub1.toString());


		
//		PKCS10CertificationRequestBuilder genReq = new PKCS10CertificationRequestBuilder(name,publicKeyInfo);
//		genReq.addAttribute(new ASN1ObjectIdentifier("2.5.4.72"), new DERPrintableString("admin:sys"));
//		PKCS10CertificationRequest request = genReq.build(sigGen); 
//    	PEMWriter pemWriter = new PEMWriter(new FileWriter(new File("D:\\certs\\request.txt")));
//    	pemWriter.writeObject(request);
//    	pemWriter.flush();	
//    	pemWriter = new PEMWriter(new FileWriter(new File("D:\\certs\\pubKey.txt")));
//    	pemWriter.writeObject(publicKey);
//    	pemWriter.flush();
//    	pemWriter = new PEMWriter(new FileWriter(new File("D:\\certs\\privKey.txt")));
//    	pemWriter.writeObject(privateKey);
//    	pemWriter.flush();
    	
    	
//    	@SuppressWarnings("deprecation")
//		PEMReader pemReader = new PEMReader(new FileReader(new File("D:\\certs\\request.txt")));
//    	PKCS10CertificationRequest csr = 
//    		    new PKCS10CertificationRequest(pemReader.readPemObject().getContent());
//    	Attribute[] attrs = csr.getAttributes();
//    	System.out.println(attrs[0].getAttrType());
//    	System.out.println(attrs[0].getAttrValues());
//    	System.out.println(csr.getSubject().toString());
		// oid for role attribute 2.5.4.72
    	// oid for clearance attribute 2.5.4.55
		
	}
}
