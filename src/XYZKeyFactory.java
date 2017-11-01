/*
 *
 * Copyright (c) 1998 Scott Oaks. All Rights Reserved.
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for NON-COMMERCIAL purposes and
 * without fee is hereby granted.
 *
 * This sample source code is provided for example only,
 * on an unsupported, as-is basis. 
 *
 * AUTHOR MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT. AUTHOR SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
 *
 * THIS SOFTWARE IS NOT DESIGNED OR INTENDED FOR USE OR RESALE AS ON-LINE
 * CONTROL EQUIPMENT IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE
 * PERFORMANCE, SUCH AS IN THE OPERATION OF NUCLEAR FACILITIES, AIRCRAFT
 * NAVIGATION OR COMMUNICATION SYSTEMS, AIR TRAFFIC CONTROL, DIRECT LIFE
 * SUPPORT MACHINES, OR WEAPONS SYSTEMS, IN WHICH THE FAILURE OF THE
 * SOFTWARE COULD LEAD DIRECTLY TO DEATH, PERSONAL INJURY, OR SEVERE
 * PHYSICAL OR ENVIRONMENTAL DAMAGE ("HIGH RISK ACTIVITIES").  AUTHOR
 * SPECIFICALLY DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FITNESS FOR
 * HIGH RISK ACTIVITIES.
 */


import java.security.*;
import java.security.spec.*;

class XYZPublicKeyEncodedSpec extends EncodedKeySpec {
	byte[] encoding;

	XYZPublicKeyEncodedSpec(byte[] b) {
		// In 1.2 beta 4, this constructor is required since the base class
		// has a constructor only with this signature
		super(b);
		encoding = new byte[b.length];
		System.arraycopy(b, 0, encoding, 0, b.length);
	}

	XYZPublicKey getKeyFromSpec() {
		return (XYZPublicKey) new XYZKey(encoding);
	}

	public byte[] getEncoded() {
		return encoding;
	}

	public String getFormat() {
		return "XYZ Special Format";
	}

	public String toString() {
		if (encoding == null)
			return "Public Spec no encoding";
		return "Public spec " + encoding[3] + encoding[2] + encoding[1] + encoding[0];
	}
}

class XYZPrivateKeyEncodedSpec extends EncodedKeySpec {
	byte[] encoding;

	XYZPrivateKeyEncodedSpec(byte[] b) {
		super(b);
		encoding = new byte[b.length];
		System.arraycopy(b, 0, encoding, 0, b.length);
	}

	XYZPrivateKey getKeyFromSpec() {
		return (XYZPrivateKey) new XYZKey(encoding);
	}

	public byte[] getEncoded() {
		return encoding;
	}

	public String getFormat() {
		return "XYZ Special Format";
	}
}

public class XYZKeyFactory extends KeyFactorySpi {

	protected PublicKey engineGeneratePublic(KeySpec ks) throws InvalidKeySpecException {
		XYZPublicKey pk;

		if (ks instanceof XYZPublicKeyEncodedSpec) {
			XYZPublicKeyEncodedSpec xks = (XYZPublicKeyEncodedSpec) ks;
			pk = new XYZPublicKey(xks.getEncoded());
		}
		else throw new InvalidKeySpecException("Wrong key specification");
		return pk;
	}

	protected PrivateKey engineGeneratePrivate(KeySpec ks) throws InvalidKeySpecException {
		XYZPrivateKey pk;

		if (ks instanceof XYZPrivateKeyEncodedSpec) {
			XYZPrivateKeyEncodedSpec xks = (XYZPrivateKeyEncodedSpec) ks;
			pk = new XYZPrivateKey(xks.getEncoded());
		}
		else throw new InvalidKeySpecException("Wrong key specification");
		return pk;
	}

	protected KeySpec engineGetKeySpec(Key k, Class keySpec) throws InvalidKeySpecException {
		if (k instanceof XYZPublicKey) {
			if (keySpec.equals(XYZPublicKeyEncodedSpec.class)) {
				return new XYZPublicKeyEncodedSpec(k.getEncoded());
			}
			else throw new InvalidKeySpecException("Wrong key specification");
		}
		else if (k instanceof XYZPrivateKey) {
			if (keySpec.equals(XYZPrivateKeyEncodedSpec.class)) {
				return new XYZPrivateKeyEncodedSpec(k.getEncoded());
			}
			else throw new InvalidKeySpecException("Wrong key specification");
		}
		else throw new InvalidKeySpecException("Wrong key specification");
	}

	protected Key engineTranslateKey(Key k) throws InvalidKeyException {
		if (k instanceof XYZKey) {
			return k;
		}
		try {
			if (k instanceof PublicKey) {
				XYZPublicKeyEncodedSpec ks =
				(XYZPublicKeyEncodedSpec) engineGetKeySpec(k, XYZPublicKeyEncodedSpec.class);
				return engineGeneratePublic(ks);
			} else if (k instanceof PrivateKey) {
				XYZPrivateKeyEncodedSpec ks =
				(XYZPrivateKeyEncodedSpec) engineGetKeySpec(k, XYZPrivateKeyEncodedSpec.class);
				return engineGeneratePrivate(ks);
			}
			else throw new InvalidKeyException("Unknown key type");
		} catch (InvalidKeySpecException ikse) {
			throw new InvalidKeyException("Unexpected key type");
		}
	}

	private static KeySpec doExport(Key k) throws Exception {
		KeyFactory kf = KeyFactory.getInstance("XYZ");
		if (k instanceof XYZPublicKey)
			return kf.getKeySpec(k, XYZPublicKeyEncodedSpec.class);
		else return kf.getKeySpec(k, XYZPrivateKeyEncodedSpec.class);
	}

	private static Key doImport(KeySpec ks) throws Exception {
		KeyFactory kf = KeyFactory.getInstance("XYZ");
		if (ks instanceof XYZPublicKeyEncodedSpec)
			return kf.generatePublic(ks);
		else return kf.generatePrivate(ks);
	}

	public static void main(String args[]) {
		try {
			Security.addProvider(new XYZProvider());
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("XYZ");
			kpg.initialize(512);
			KeyPair kp = kpg.generateKeyPair();
			System.out.println("Got key pair::" + kp);
			System.out.println("Got key private::" + kp.getPrivate().toString());
			System.out.println("Got key public::" + kp.getPublic().getEncoded());

			KeySpec ks = doExport(kp.getPublic());
			Key k = doImport(ks);
			System.out.println("Compare keys is " + k.equals(kp.getPublic()));
	
			ks = doExport(kp.getPrivate());
			k = doImport(ks);
			System.out.println("Compare keys is " + k.equals(kp.getPrivate()));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
