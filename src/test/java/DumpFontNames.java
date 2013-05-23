import java.util.Iterator;
import java.util.TreeMap;

import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;

public class DumpFontNames {

    static PdfReader reader;

    static TreeMap fontMap = new TreeMap();

    static final PdfName F1 = new PdfName("FontFile");

    static final PdfName F2 = new PdfName("FontFile2");

    static final PdfName F3 = new PdfName("FontFile3");

    public static void processResource(PdfDictionary resource) throws Exception {
	if (resource == null)
	    return;
	PdfDictionary xos = (PdfDictionary) reader.getPdfObject(resource.get(PdfName.XOBJECT));
	if (xos != null) {
	    for (Iterator it = xos.getKeys().iterator(); it.hasNext();) {
		PdfDictionary xo = (PdfDictionary) reader.getPdfObject(xos.get((PdfName) it.next()));
		processResource((PdfDictionary) reader.getPdfObject(xo.get(PdfName.RESOURCES)));
	    }
	}
	PdfDictionary fonts = (PdfDictionary) reader.getPdfObject(resource.get(PdfName.FONT));
	if (fonts == null)
	    return;
	for (Iterator it = fonts.getKeys().iterator(); it.hasNext();) {
	    PdfDictionary font = (PdfDictionary) reader.getPdfObject(fonts.get((PdfName) it.next()));
	    String name = ((PdfName) reader.getPdfObject(font.get(PdfName.BASEFONT))).toString();
	    System.out.println("basefont=" + name);
	    // System.out.println("name="+reader.getPdfObject(font.get(PdfName.NAME)));
	    System.out.println("encoding=" + reader.getPdfObject(font.get(PdfName.ENCODING)));
	    System.out.println("subType=" + reader.getPdfObject(font.get(PdfName.SUBTYPE)));
	    if (name.length() > 8 && name.charAt(7) == '+') {
		name = name.substring(8) + " subset";
	    } else {
		name = name.substring(1);
	    }
	    PdfDictionary desc = (PdfDictionary) reader.getPdfObject(font.get(PdfName.FONTDESCRIPTOR));
	    if (desc == null) {
		PdfArray arr = (PdfArray) reader.getPdfObject(font.get(PdfName.DESCENDANTFONTS)); // For Type0 fonts
		System.out.println("array=" + arr.getAsDict(0));
		desc = (PdfDictionary) reader.getPdfObject(arr.getAsDict(0).get(PdfName.FONTDESCRIPTOR));
	    }
	    System.out.println("desc=" + desc);
	    if (desc != null) {
		System.out.println("fontname=" + desc.get(PdfName.FONTNAME));
		if (desc.get(F1) != null || desc.get(F2) != null || desc.get(F3) != null)
		    name += " embedded";
	    } else
		name += " nofontdescriptor";
	    fontMap.put(name, null);
	}
    }

    public static void main(String[] args) {
	try {
	    reader = new PdfReader("src/test/resources/MyPDF.pdf");
	    for (int k = 1; k <= reader.getNumberOfPages(); ++k) {
		PdfDictionary page = reader.getPageN(k);
		processResource((PdfDictionary) reader.getPdfObject(page.get(PdfName.RESOURCES)));
	    }
	    for (Iterator it = fontMap.keySet().iterator(); it.hasNext();)
		System.out.println((String) it.next());
	} catch (Exception e) {
	    e.printStackTrace();
	}
    }
}