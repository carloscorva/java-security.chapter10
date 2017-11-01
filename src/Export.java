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
import java.io.*;

public class Export {
	public static void main(String args[]) {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
			kpg.initialize(512, new SecureRandom());
			KeyPair kp = kpg.generateKeyPair();
			Class spec = Class.forName("java.security.spec.DSAPrivateKeySpec");
			KeyFactory kf = KeyFactory.getInstance("DSA");
			DSAPrivateKeySpec ks = (DSAPrivateKeySpec) kf.getKeySpec(kp.getPrivate(), spec);
			FileOutputStream fos = new FileOutputStream("exportedKey");
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			System.out.println("provider " + kf.getProvider());
			oos.writeObject(ks.getX());
			oos.writeObject(ks.getP());
			oos.writeObject(ks.getQ());
			oos.writeObject(ks.getG());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
