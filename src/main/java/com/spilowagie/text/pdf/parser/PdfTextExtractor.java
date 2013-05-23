/*
 * Copyright 2008 by Kevin Day.
 *
 * The contents of this file are subject to the Mozilla Public License Version 1.1
 * (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the License.
 *
 * The Original Code is 'iText, a free JAVA-PDF library'.
 *
 * The Initial Developer of the Original Code is Bruno Lowagie. Portions created by
 * the Initial Developer are Copyright (C) 1999-2008 by Bruno Lowagie.
 * All Rights Reserved.
 * Co-Developer of the code is Paulo Soares. Portions created by the Co-Developer
 * are Copyright (C) 2000-2008 by Paulo Soares. All Rights Reserved.
 *
 * Contributor(s): all the names of the contributors are added in the source code
 * where applicable.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * LGPL license (the "GNU LIBRARY GENERAL PUBLIC LICENSE"), in which case the
 * provisions of LGPL are applicable instead of those above.  If you wish to
 * allow use of your version of this file only under the terms of the LGPL
 * License and not to allow others to use your version of this file under
 * the MPL, indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the LGPL.
 * If you do not delete the provisions above, a recipient may use your version
 * of this file under either the MPL or the GNU LIBRARY GENERAL PUBLIC LICENSE.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MPL as stated above or under the terms of the GNU
 * Library General Public License as published by the Free Software Foundation;
 * either version 2 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Library general Public License for more
 * details.
 *
 * If you didn't download this code from the following link, you should check if
 * you aren't using an obsolete version:
 * http://www.lowagie.com/iText/
 */
package com.spilowagie.text.pdf.parser;

import java.io.IOException;

import com.spilowagie.text.pdf.PdfDictionary;
import com.spilowagie.text.pdf.PdfName;
import com.spilowagie.text.pdf.PdfReader;
import com.spilowagie.text.pdf.RandomAccessFileOrArray;

/**
 * Extracts text from a PDF file.
 * @since	2.1.4
 */
public class PdfTextExtractor {

	/** The PdfReader that holds the PDF file. */
    private final PdfReader reader;
    /** The processor that will extract the text. */
    private final SimpleTextExtractingPdfContentStreamProcessor extractionProcessor;
    
    /**
     * Creates a new Text Extractor object.
     * @param reader	the reader with the PDF
     */
    public PdfTextExtractor(PdfReader reader) {
        this.reader = reader;
        extractionProcessor = new SimpleTextExtractingPdfContentStreamProcessor();
    }

    /**
     * Gets the content stream of a page.
     * @param pageNum	the page number of page you want get the content stream from
     * @return	a byte array with the content stream of a page
     * @throws IOException
     */
    private byte[] getContentBytesForPage(int pageNum) throws IOException {
        RandomAccessFileOrArray f = reader.getSafeFile();
        byte[] contentBytes = reader.getPageContent(pageNum, f);
        f.close();
        return contentBytes;
    }
    
    /**
     * Gets the text from a page.
     * @param page	the page number of the page
     * @return	a String with the content as plain text (without PDF syntax)
     * @throws IOException
     */
    public String getTextFromPage(int page) throws IOException {
        PdfDictionary pageDic = reader.getPageN(page);
        PdfDictionary resourcesDic = pageDic.getAsDict(PdfName.RESOURCES);
        extractionProcessor.processContent(getContentBytesForPage(page), resourcesDic);        
        return extractionProcessor.getResultantText();
    }
}