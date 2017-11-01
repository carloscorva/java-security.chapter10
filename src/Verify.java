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


import java.security.cert.*;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.io.*;
import java.math.*;

public class Verify {
	public Certificate importCertificate(byte data[]) throws CertificateException {
		X509Certificate c = null;
		try {
			// In 1.2 beta 4, the following method no longer exists, and we
			// must use a certificate factory instead
			// c = X509Certificate.getInstance(data);
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			ByteArrayInputStream bais = new ByteArrayInputStream(data);
			Certificate cert = cf.generateCertificate(bais);
			c = (X509Certificate) cert;

			Principal p = c.getIssuerDN();
			PublicKey pk = getPublicKey(p);
			c.verify(pk);
			InputStream crlFile = lookupCRLFile(p);

			// In 1.2 beta 4, the following method no longer exists, and we
			// must use a certificate factory instead
			// X509CRL crl = X509CRL.getInstance(crlFile);
			cf = CertificateFactory.getInstance("X509CRL");
			X509CRL crl = (X509CRL) cf.generateCRL(crlFile);

			if (crl.isRevoked(c))
				throw new CertificateException("Certificate is revoked");
		} catch (NoSuchAlgorithmException nsae) {
			throw new CertificateException("Can't verify certificate");
		} catch (NoSuchProviderException nspe) {
			throw new CertificateException("Can't verify certificate");
		} catch (SignatureException se) {
			throw new CertificateException("Can't verify certificate");
		} catch (InvalidKeyException ike) {
			throw new CertificateException("Can't verify certificate");
		} catch (CRLException ce) {
			// treat as no crl
		}
		return c;
	}

	private native InputStream lookupCRLFile(Principal p);
	private native PublicKey getPublicKey(Principal p);
}
