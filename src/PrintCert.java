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
import java.io.*;

public class PrintCert {
	public static void main(String args[]) {
		try {
			FileInputStream fr = new FileInputStream("sdo.cer");
			// In 1.2 beta 4, the following method no longer exists, and
			// we have to use a certificate factory instead
			// X509Certificate c = X509Certificate.getInstance(fr);
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			Certificate cert = cf.generateCertificate(fr);
			X509Certificate c = (X509Certificate) cert;
			System.out.println("Read in the following certificate:");
			System.out.println("\tCertificate for: " + c.getSubjectDN());
			System.out.println("\tCertificate issued by: " + c.getIssuerDN());
			System.out.println("\tThe certificate is valid from " +
						c.getNotBefore() + " to " + c.getNotAfter());
			System.out.println("\tCertificate SN# " + c.getSerialNumber());
			System.out.println("\tGenerated with " + c.getSigAlgName());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
