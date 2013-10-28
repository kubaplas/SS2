import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.io.pem.PemReader;


public class UserParty 
{
	private X509CertificateHolder my_certificate;
	
	private PrivateKey dh_private_key;
	private PublicKey dh_public_key;
	
	private PrivateKey private_key;
	private PublicKey public_key;
	
	private PublicKey buddy_public_key;
	private PublicKey buddy_dh_public_key;
	
	private byte[] gxy;
	
	private SecretKey secret_ks;
	private SecretKey secret_km;
	
	private byte[] signature;
	private byte[] signature2;
	
	private byte[] MAC;
	
	
	private DHParameterSpec params;
	
	private X509CertificateHolder buddy_certificate;
//	"D:\\certs\\CAcert.crt"
	
	public void load_certificate(String cert_colation) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
	{
		PemReader pemReaderCerts = new PemReader(new FileReader(new File(cert_colation)));
    	this.my_certificate = new X509CertificateHolder(pemReaderCerts.readPemObject().getContent());
    	pemReaderCerts.close();
    	
    	
    	SubjectPublicKeyInfo pubKeyCa = this.my_certificate.getSubjectPublicKeyInfo();
    	RSAKeyParameters pk1 = (RSAKeyParameters) PublicKeyFactory.createKey(pubKeyCa.getPublicKeyData().getBytes());
    	RSAPublicKeySpec rsaSpec1 = new RSAPublicKeySpec(pk1.getModulus(), pk1.getExponent());
    	KeyFactory kf1 = KeyFactory.getInstance("RSA");
    	this.public_key = kf1.generatePublic(rsaSpec1);
    	
    	
	}
	
	public void load_private_key(String key_location) throws IOException
	{
		BufferedReader br = new BufferedReader(new FileReader(key_location));
		KeyPair kp = (KeyPair) new PEMReader(br).readObject();
		this.private_key = kp.getPrivate();
	}
	
	public void generate_DH_keys() throws NoSuchAlgorithmException
	{
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DH");
		keyGenerator.initialize(512);
		KeyPair kpair = keyGenerator.genKeyPair();
		this.dh_private_key = kpair.getPrivate();
		this.dh_public_key = kpair.getPublic();
		this.params = 
			    ((javax.crypto.interfaces.DHPublicKey) this.dh_public_key).getParams();
	}
	
	public void set_buddy_certificate(X509CertificateHolder buddy_certificate) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
	{
		this.buddy_certificate = buddy_certificate;
		
		SubjectPublicKeyInfo pubKeyCa = this.buddy_certificate.getSubjectPublicKeyInfo();
    	RSAKeyParameters pk1 = (RSAKeyParameters) PublicKeyFactory.createKey(pubKeyCa.getPublicKeyData().getBytes());
    	RSAPublicKeySpec rsaSpec1 = new RSAPublicKeySpec(pk1.getModulus(), pk1.getExponent());
    	KeyFactory kf1 = KeyFactory.getInstance("RSA");
    	this.buddy_public_key = kf1.generatePublic(rsaSpec1);
	}
	
	public void set_buddy_dh_public_key(PublicKey public_key)
	{
		this.buddy_dh_public_key = public_key;
	}
	
	
	public X509CertificateHolder get_certificate()
	{
		return this.my_certificate;
	}
	
	public BigInteger get_P()
	{
		return this.params.getP();
	}
	
	public BigInteger get_G()
	{
		return this.params.getG();
	}
	
	  
	public BigInteger get_Y()
	{
		return ((javax.crypto.interfaces.DHPublicKey) this.dh_public_key).getY();
	}
	
	public BigInteger get_X()
	{
		return ((javax.crypto.interfaces.DHPrivateKey) this.dh_private_key).getX();
	}
	
	public PrivateKey get_dh_private_key()
	{
		return this.dh_private_key;
	}
	
	public PublicKey get_dh_public_key()
	{
		return this.dh_public_key;
	}
	
	public BigInteger get_buddy_Y()
	{
		return ((javax.crypto.interfaces.DHPublicKey) this.buddy_dh_public_key).getY();
	}
	
	public PublicKey get_buddy_dh_public_key()
	{
		return this.buddy_dh_public_key;
	}
	
	
	public SecretKey get_secret_ks() {
		return secret_ks;
	}

	public void set_secret_ks(SecretKey secret_ks) {
		this.secret_ks = secret_ks;
	}

	public SecretKey get_secret_km() {
		return secret_km;
	}

	public void set_secret_km(SecretKey secret_km) {
		this.secret_km = secret_km;
	}
	
	public byte[] get_signature() {
		return signature;
	}

	public void set_signature(byte[] signature) {
		this.signature = signature;
	}

	public void compute_gxy()
	{
		byte[] gxy = this.get_buddy_Y().modPow(this.get_X(), this.get_P()).toByteArray();
		this.gxy = gxy;
	}
	
	public void compute_secret_ks()
	{
		SecureRandom sec_rand = new SecureRandom(this.gxy);
		byte[] sec_bytes = new byte[32];
		sec_rand.nextBytes(sec_bytes);
		SecretKey originalKey = new SecretKeySpec(sec_bytes, 0, sec_bytes.length, "AES");
		this.set_secret_ks(originalKey);
	}
	
	public void compute_secret_km()
	{
		SecretKey originalKey = new SecretKeySpec(this.gxy, 0, 32, "AES");
		this.set_secret_km(originalKey);
		
	}
	
	public byte[] get_signature2() {
		return signature2;
	}

	public void set_signature2(byte[] signature2) {
		this.signature2 = signature2;
	}

	public byte[] get_MAC() {
		return MAC;
	}

	public void set_MAC(byte[] mAC) {
		MAC = mAC;
	}

	public static void main(String args[]) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		UserParty party1 = new UserParty();
		UserParty party2 = new UserParty();
		
		party1.generate_DH_keys();
		party1.load_certificate("D:\\certs\\CAcert.crt");
		party1.load_private_key("D:\\certs\\privateCA.pem");
		
		
		party2.generate_DH_keys();
		party2.load_certificate("D:\\certs\\ZIOMcert.crt");
		party2.load_private_key("D:\\certs\\privateZIOM.pem");
		
		party1.set_buddy_certificate(party2.get_certificate());
		
		party2.set_buddy_certificate(party1.get_certificate());
		
		
		// Krok pierwszy! Party1 "wysyla" do Party2 klucz publiczny DH
		party2.set_buddy_dh_public_key(party1.get_dh_public_key());
		
		// Krok drugi! Party2 odsy³a do Party1 : swoj klucz publiczny DH, swoje ID (certyfikat), podpisane oba dh klucze publiczne
		// oraz MAC swojego ID z kluczem wyciagnietym z dh klucza publicznego party 1 oraz swojego dh prywatnego y
		
		//wyslanie publicznego DH
		party1.set_buddy_dh_public_key(party2.get_dh_public_key());
		//wyslanie swojego certyfikatu
		party1.set_buddy_certificate(party2.get_certificate());
		
		
		//wysylanie podpisow
		Signature rsa_sign = Signature.getInstance("SHA1withRSA");
		rsa_sign.initSign(party2.private_key);
		byte[] to_sign = party2.get_buddy_dh_public_key().getEncoded();
		rsa_sign.update(to_sign);
		party1.set_signature(rsa_sign.sign());
		
		//wysylanie podpisow
		rsa_sign = Signature.getInstance("SHA1withRSA");
		rsa_sign.initSign(party2.private_key);
		byte[] to_sign2 = party2.get_dh_public_key().getEncoded();
		rsa_sign.update(to_sign2);
		party1.set_signature2(rsa_sign.sign());
		
		
		//W miedzyczasie party 2 oblicza sobie g^xy oraz pozniej klucze Km oraz Ks
		party2.compute_gxy();
		party2.compute_secret_km();
		party2.compute_secret_ks();
		
		
		// Party 2 uzywa klucza Km do nadania wiadomosci MAC do party 1
		
		
		Mac mac = Mac.getInstance("HmacSHA1");
	    mac.init(party2.get_secret_km());
	    mac.update(party2.get_certificate().getEncoded());
	    //wysylanie maca
	    party1.set_MAC(mac.doFinal());
	    
		
	    // 	koniec kroku trzeciego!!		

	    //Podczas kroku trzeciego, najpierw party1 sprawdza sobie wszystko co dostal!!
	    
	    //sprawdzenie podpisow
	    Signature rsa_sign_ver = Signature.getInstance("SHA1withRSA");
	    Signature rsa_sign_ver1 = Signature.getInstance("SHA1withRSA");
	    rsa_sign_ver.initVerify(party1.buddy_public_key);
	    rsa_sign_ver1.initVerify(party1.buddy_public_key);
	    
	    rsa_sign_ver.update(party1.get_dh_public_key().getEncoded());
	    rsa_sign_ver1.update(party1.get_buddy_dh_public_key().getEncoded());
	    
	    if(!rsa_sign_ver.verify(party1.signature))
	    {
	    	throw new Exception("Invalid signature!");
	    }
	    
	    if(!rsa_sign_ver1.verify(party1.signature2))
	    {
	    	throw new Exception("Invalid signature!");
	    }
	    
	    
	    party1.compute_gxy();
	    party1.compute_secret_km();
	    party1.compute_secret_ks();
	    
	    
	    //sprawdzenie wiadomosci MAC
	    
	    Mac mac2 = Mac.getInstance("HmacSHA1");
	    mac2.init(party1.get_secret_km());
	    mac2.update(party1.buddy_certificate.getEncoded());
	    byte[] mac_bytes = mac2.doFinal();
	    byte[] mac_bytes2 = party1.get_MAC();
	    for(int i = 0; i < mac_bytes.length; i++)
	    {
	    	if(mac_bytes[i] != mac_bytes2[i])
	    	{
	    		throw new Exception("Invalid MAC message");
	    	}
	    }
	    
	    
	    // Wszystko dziala bez problemow to teraz party 1 wysyla wszystko co potrzebne do dwojki
	    
	    // tzn swoj certyfikat
	    party2.set_buddy_certificate(party1.get_certificate());
	    
	    // podpisane klucze publiczne dh
	    
	    
	  //wysylanie podpisow
  		rsa_sign = Signature.getInstance("SHA1withRSA");
  		rsa_sign.initSign(party1.private_key);
  		to_sign = party1.get_buddy_dh_public_key().getEncoded();
  		rsa_sign.update(to_sign);
  		party2.set_signature(rsa_sign.sign());
  		
  		//wysylanie podpisow
  		rsa_sign = Signature.getInstance("SHA1withRSA");
  		rsa_sign.initSign(party1.private_key);
  		to_sign2 = party1.get_dh_public_key().getEncoded();
  		rsa_sign.update(to_sign2);
  		party2.set_signature2(rsa_sign.sign());
  		
  	
  		//oraz MAC swojego certyfikatu
	    
	    
  		mac = Mac.getInstance("HmacSHA1");
	    mac.init(party1.get_secret_km());
	    mac.update(party1.get_certificate().getEncoded());
	    //wysylanie maca
	    party2.set_MAC(mac.doFinal());
	    
	    
	    // No i ostatni krok, 'niemy' gdzie party 2 sprawdza to co dostalo od party1 w poprzednim kroku
	    
	    
	    rsa_sign_ver = Signature.getInstance("SHA1withRSA");
	    rsa_sign_ver1 = Signature.getInstance("SHA1withRSA");
	    rsa_sign_ver.initVerify(party2.buddy_public_key);
	    rsa_sign_ver1.initVerify(party2.buddy_public_key);
	    
	    rsa_sign_ver.update(party2.get_dh_public_key().getEncoded());
	    rsa_sign_ver1.update(party2.get_buddy_dh_public_key().getEncoded());
	    
	    if(!rsa_sign_ver.verify(party2.signature))
	    {
	    	throw new Exception("Invalid signature!");
	    }
	    
	    if(!rsa_sign_ver1.verify(party2.signature2))
	    {
	    	throw new Exception("Invalid signature!");
	    }
	    
	    
	    mac2 = Mac.getInstance("HmacSHA1");
	    mac2.init(party2.get_secret_km());
	    mac2.update(party2.buddy_certificate.getEncoded());
	    mac_bytes = mac2.doFinal();
	    mac_bytes2 = party2.get_MAC();
	    for(int i = 0; i < mac_bytes.length; i++)
	    {
	    	if(mac_bytes[i] != mac_bytes2[i])
	    	{
	    		throw new Exception("Invalid MAC message");
	    	}
	    }
	    
	    
	    
	    
	    
	    
	    
	    byte[] km1 = party1.get_secret_km().getEncoded();
	    byte[] km2 = party2.get_secret_km().getEncoded();
	    
	    for(int i = 0; i < km1.length; i ++)
	    {
	    	System.out.print(km1[i] + " ");
	    }
	    System.out.println("");
	    for(int i = 0; i < km2.length; i ++)
	    {
	    	System.out.print(km2[i] + " ");
	    }
	    System.out.println("");
	    byte[] ks1 = party1.get_secret_ks().getEncoded();
	    byte[] ks2 = party2.get_secret_ks().getEncoded();
	    
	    for(int i = 0; i < ks1.length; i ++)
	    {
	    	System.out.print(ks1[i] + " ");
	    }
	    System.out.println("");
	    for(int i = 0; i < ks2.length; i ++)
	    {
	    	System.out.print(ks2[i] + " ");
	    }
	    
	    
		
		
		
				
				
		
	}

	
	

}
