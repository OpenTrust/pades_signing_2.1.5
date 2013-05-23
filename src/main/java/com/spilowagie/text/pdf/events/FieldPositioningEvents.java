/*
 * Copyright 2005 by Bruno Lowagie
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
 * the Initial Developer are Copyright (C) 1999-2005 by Bruno Lowagie.
 * All Rights Reserved.
 * Co-Developer of the code is Paulo Soares. Portions created by the Co-Developer
 * are Copyright (C) 2000-2005 by Paulo Soares. All Rights Reserved.
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
package com.spilowagie.text.pdf.events;

import java.io.IOException;
import java.util.LinkedHashMap;

import com.spilowagie.text.Document;
import com.spilowagie.text.DocumentException;
import com.spilowagie.text.ExceptionConverter;
import com.spilowagie.text.Rectangle;
import com.spilowagie.text.pdf.PdfContentByte;
import com.spilowagie.text.pdf.PdfFormField;
import com.spilowagie.text.pdf.PdfName;
import com.spilowagie.text.pdf.PdfPCell;
import com.spilowagie.text.pdf.PdfPCellEvent;
import com.spilowagie.text.pdf.PdfPageEventHelper;
import com.spilowagie.text.pdf.PdfRectangle;
import com.spilowagie.text.pdf.PdfWriter;
import com.spilowagie.text.pdf.TextField;

/**
 * Class that can be used to position AcroForm fields.
 */
public class FieldPositioningEvents extends PdfPageEventHelper implements PdfPCellEvent {

    /**
     * Keeps a map with fields that are to be positioned in inGenericTag.
     */
    protected LinkedHashMap genericChunkFields = new LinkedHashMap();

    /**
     * Keeps the form field that is to be positioned in a cellLayout event.
     */
    protected PdfFormField cellField = null;
    
    /**
     * The PdfWriter to use when a field has to added in a cell event. 
     */
    protected PdfWriter fieldWriter = null;
    /**
     * The PdfFormField that is the parent of the field added in a cell event. 
     */
    protected PdfFormField parent = null;
    
    /** Creates a new event. This constructor will be used if you need to position fields with Chunk objects. */
    public FieldPositioningEvents() {}
    
    /** Some extra padding that will be taken into account when defining the widget. */
    public float padding;
    
    /**
     * Add a PdfFormField that has to be tied to a generic Chunk.
     */
    public void addField(String text, PdfFormField field) {
    	genericChunkFields.put(text, field);
    }
    
    /** Creates a new event. This constructor will be used if you need to position fields with a Cell Event. */
    public FieldPositioningEvents(PdfWriter writer, PdfFormField field) {
    	this.cellField = field;
    	this.fieldWriter = writer;
    }  
    
    /** Creates a new event. This constructor will be used if you need to position fields with a Cell Event. */
    public FieldPositioningEvents(PdfFormField parent, PdfFormField field) {
    	this.cellField = field;
    	this.parent = parent;
    }
    
    /** Creates a new event. This constructor will be used if you need to position fields with a Cell Event. 
     * @throws DocumentException
     * @throws IOException*/
    public FieldPositioningEvents(PdfWriter writer, String text) throws IOException, DocumentException {
    	this.fieldWriter = writer;
    	TextField tf = new TextField(writer, new Rectangle(0, 0), text);
		tf.setFontSize(14);
		cellField = tf.getTextField();
	}   
    
    /** Creates a new event. This constructor will be used if you need to position fields with a Cell Event. 
     * @throws DocumentException
     * @throws IOException*/
    public FieldPositioningEvents(PdfWriter writer, PdfFormField parent, String text) throws IOException, DocumentException {
    	this.parent = parent;
    	TextField tf = new TextField(writer, new Rectangle(0, 0), text);
		tf.setFontSize(14);
		cellField = tf.getTextField();
	}  

	/**
	 * @param padding The padding to set.
	 */
	public void setPadding(float padding) {
		this.padding = padding;
	}
	
	/**
	 * @param parent The parent to set.
	 */
	public void setParent(PdfFormField parent) {
		this.parent = parent;
	}
	/**
	 * @see com.spilowagie.text.pdf.PdfPageEvent#onGenericTag(com.spilowagie.text.pdf.PdfWriter, com.spilowagie.text.Document, com.spilowagie.text.Rectangle, java.lang.String)
	 */
	public void onGenericTag(PdfWriter writer, Document document,
			Rectangle rect, String text) {
		rect.setBottom(rect.getBottom() - 3);
		PdfFormField field = (PdfFormField) genericChunkFields.get(text);
		if (field == null) {
			TextField tf = new TextField(writer, new Rectangle(rect.getLeft(padding), rect.getBottom(padding), rect.getRight(padding), rect.getTop(padding)), text);
			tf.setFontSize(14);
			try {
				field = tf.getTextField();
			} catch (Exception e) {
				throw new ExceptionConverter(e);
			}
		}
		else {
			field.put(PdfName.RECT,  new PdfRectangle(rect.getLeft(padding), rect.getBottom(padding), rect.getRight(padding), rect.getTop(padding)));
		}
		if (parent == null)
			writer.addAnnotation(field);
		else
			parent.addKid(field);
	}

	/**
	 * @see com.spilowagie.text.pdf.PdfPCellEvent#cellLayout(com.spilowagie.text.pdf.PdfPCell, com.spilowagie.text.Rectangle, com.spilowagie.text.pdf.PdfContentByte[])
	 */
	public void cellLayout(PdfPCell cell, Rectangle rect, PdfContentByte[] canvases) {
		if (cellField == null || (fieldWriter == null && parent == null)) throw new ExceptionConverter(new IllegalArgumentException("You have used the wrong constructor for this FieldPositioningEvents class."));
		cellField.put(PdfName.RECT, new PdfRectangle(rect.getLeft(padding), rect.getBottom(padding), rect.getRight(padding), rect.getTop(padding)));
		if (parent == null)
			fieldWriter.addAnnotation(cellField);
		else
			parent.addKid(cellField);
	}
}