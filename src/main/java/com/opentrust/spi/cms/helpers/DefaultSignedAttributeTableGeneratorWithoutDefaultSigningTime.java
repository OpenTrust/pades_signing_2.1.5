package com.opentrust.spi.cms.helpers;

import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSAttributeTableGenerator;

// similar to DefaultSignedAttributeTableGenerator BouncyCastle class, but does not add signing time
public class DefaultSignedAttributeTableGeneratorWithoutDefaultSigningTime implements CMSAttributeTableGenerator {
 	private final Hashtable table;
 	
 	public DefaultSignedAttributeTableGeneratorWithoutDefaultSigningTime(AttributeTable signedAttributesTable) {
        if(signedAttributesTable != null)
            table = signedAttributesTable.toHashtable();
        else
            table = new Hashtable();
	}
 	
     public AttributeTable getAttributes(Map map) {
         return new AttributeTable(createStandardAttributeTable(map));
     }

     protected Hashtable createStandardAttributeTable(Map map) {
        Hashtable hashtable = (Hashtable)table.clone();
        if(!hashtable.containsKey(CMSAttributes.contentType)) {
            DERObjectIdentifier derobjectidentifier = (DERObjectIdentifier)map.get("contentType");
            if(derobjectidentifier != null) {
                Attribute attribute = new Attribute(CMSAttributes.contentType, new DERSet(derobjectidentifier));
                hashtable.put(attribute.getAttrType(), attribute);
            }
        }
        if(!hashtable.containsKey(CMSAttributes.messageDigest)) {
            byte abyte0[] = (byte[])(byte[])map.get("digest");
            Attribute attribute2 = new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(abyte0)));
            hashtable.put(attribute2.getAttrType(), attribute2);
        }
        return hashtable;
    }
}
