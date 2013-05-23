package com.opentrust.spi.pdf;

import java.util.Iterator;
import java.util.TreeMap;

import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.PRIndirectReference;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;
import com.opentrust.spi.crypto.ExceptionHandler;
import com.opentrust.spi.logger.Channel;
import com.opentrust.spi.logger.SPILogger;


public class PDFFontHelper {
	private static SPILogger log = SPILogger.getLogger("PDFSIGN");

    static TreeMap fontMap = new TreeMap();

    static final PdfName F1 = new PdfName("FontFile");

    static final PdfName F2 = new PdfName("FontFile2");

    static final PdfName F3 = new PdfName("FontFile3");

    public static void processResource(PdfDictionary resource) throws Exception {
		if (resource == null)
		    return;
		PdfDictionary xos = (PdfDictionary) PdfReader.getPdfObject(resource.get(PdfName.XOBJECT));
		if (xos != null) {
		    for (Iterator it = xos.getKeys().iterator(); it.hasNext();) {
			PdfDictionary xo = (PdfDictionary) PdfReader.getPdfObject(xos.get((PdfName) it.next()));
			processResource((PdfDictionary) PdfReader.getPdfObject(xo.get(PdfName.RESOURCES)));
		    }
		}
		PdfDictionary fonts = (PdfDictionary) PdfReader.getPdfObject(resource.get(PdfName.FONT));
		if (fonts == null)
		    return;
		for (Iterator it = fonts.getKeys().iterator(); it.hasNext();) {
			PdfName internalName = (PdfName)it.next();
	    	
			log.debug(Channel.TECH, "processResource.Font=%1$s", internalName.toString());
		    PdfDictionary font = (PdfDictionary) PdfReader.getPdfObject(fonts.get(internalName));
		    
		    String name = ((PdfName) PdfReader.getPdfObject(font.get(PdfName.BASEFONT))).toString();
		    
			log.debug(Channel.TECH, "basefont=%1$s", name);
			log.debug(Channel.TECH, "encoding=%1$s", PdfReader.getPdfObject(font.get(PdfName.ENCODING)));
			log.debug(Channel.TECH, "subType=%1$s", PdfReader.getPdfObject(font.get(PdfName.SUBTYPE)));

		    if (name.length() > 8 && name.charAt(7) == '+') {
			name = name.substring(8) + " subset";
		    } else {
			name = name.substring(1);
		    }
		    PdfDictionary desc = (PdfDictionary) PdfReader.getPdfObject(font.get(PdfName.FONTDESCRIPTOR));
		    if (desc == null) {
				PdfArray arr = (PdfArray) PdfReader.getPdfObject(font.get(PdfName.DESCENDANTFONTS)); // For Type0 fonts
				log.debug(Channel.TECH, "array=%1$s", arr.getAsDict(0));
				desc = (PdfDictionary) PdfReader.getPdfObject(arr.getAsDict(0).get(PdfName.FONTDESCRIPTOR));
		    }
			log.debug(Channel.TECH, "desc=%1$s", desc);
		    if (desc != null) {
				log.debug(Channel.TECH, "fontname=%1$s", desc.get(PdfName.FONTNAME));
				if (desc.get(F1) != null || desc.get(F2) != null || desc.get(F3) != null)
					name += " embedded";
		    } else
		    	name += " nofontdescriptor";
		    
		    PdfName baseFontName = (PdfName) PdfReader.getPdfObject(fonts.get(PdfName.BASEFONT));
		    log.debug(Channel.TECH, "baseFontName=%1$s", baseFontName);
		    PRIndirectReference iRef = (PRIndirectReference) fonts.get(internalName);
		    log.debug(Channel.TECH, "iRef=%1$s", iRef);
		    fontMap.put(name, BaseFont.createFont(iRef));
		}
    }

    public static BaseFont getFirstBaseFont(PdfReader reader) {
		try {
		    for (int k = 1; k <= reader.getNumberOfPages(); ++k) {
				PdfDictionary page = reader.getPageN(k);
				BaseFont bFont = getFirstBaseFont(page);
				if(bFont!=null) return bFont;
		    }
		} catch (Exception e) {
		    ExceptionHandler.handle(e);
		}
		return null;
    }
    
    private static BaseFont getFirstBaseFont(PdfDictionary page) {
    	PdfDictionary resource = (PdfDictionary) PdfReader.getPdfObject(page.get(PdfName.RESOURCES));
    	if(resource!=null) {
    		PdfDictionary fonts = (PdfDictionary) PdfReader.getPdfObject(resource.get(PdfName.FONT));
    		if (fonts == null) return null;
    		for (Object iName : fonts.getKeys()) {
    			PdfName internalName = (PdfName)iName;
    			log.debug(Channel.TECH, "getFirstBaseFont.Font : %1$s", internalName);
    		    PdfDictionary font = (PdfDictionary) PdfReader.getPdfObject(fonts.get(internalName));
//    		    PdfName subtype = (PdfName)reader.getPdfObject(font.get(PdfName.SUBTYPE));
//    		    log.debug(Channel.TECH, "getFirstBaseFont.subType : %1$s", subtype);
     		    PRIndirectReference iRef = (PRIndirectReference) fonts.get(internalName);
     		    
     		    return BaseFont.createFont(iRef);
    		    //Voir pourquoi ne fonctionn pas quand on a par exemple un subtype=/Type1
    		}
    	}
    	return null;
    }
}