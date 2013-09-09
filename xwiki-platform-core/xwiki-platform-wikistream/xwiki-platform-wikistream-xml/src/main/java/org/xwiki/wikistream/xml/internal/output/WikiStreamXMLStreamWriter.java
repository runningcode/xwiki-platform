/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.wikistream.xml.internal.output;

import java.io.OutputStream;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.xwiki.wikistream.WikiStreamException;

/**
 * 
 * @version $Id$
 * @since 5.2M2
 */
public class WikiStreamXMLStreamWriter
{
    private final XMLStreamWriter writer;

    public WikiStreamXMLStreamWriter(XMLStreamWriter writer)
    {
        this.writer = writer;
    }

    public WikiStreamXMLStreamWriter(OutputStream outputStream, String encoding) throws WikiStreamException
    {
        try {
            this.writer = XMLOutputFactory.newInstance().createXMLStreamWriter(outputStream, encoding);
        } catch (Exception e) {
            throw new WikiStreamException("Failed to create XML writer", e);
        }
    }

    public WikiStreamXMLStreamWriter(XMLOuputProperties properties) throws WikiStreamException
    {
        try {
            this.writer = XMLOutputWikiStreamUtils.createXMLStreamWriter(properties);
        } catch (Exception e) {
            throw new WikiStreamException("Failed to create XML writer", e);
        }
    }

    public XMLStreamWriter getWriter()
    {
        return writer;
    }

    //

    /**
     * Write the XML Declaration. Defaults the XML version to 1.0, and the encoding to utf-8
     * 
     * @throws WikiStreamException
     */
    public void writeStartDocument() throws WikiStreamException
    {
        try {
            this.writer.writeStartDocument();
        } catch (XMLStreamException e) {
            throw new WikiStreamException("Failed to write start document", e);
        }
    }

    /**
     * Closes any start tags and writes corresponding end tags.
     * 
     * @throws WikiStreamException
     */
    public void writeEndDocument() throws WikiStreamException
    {
        try {
            this.writer.writeEndDocument();
        } catch (XMLStreamException e) {
            throw new WikiStreamException("Failed to write end document", e);
        }
    }

    public void writeEmptyElement(String localName) throws WikiStreamException
    {
        try {
            this.writer.writeEmptyElement(localName);
        } catch (XMLStreamException e) {
            throw new WikiStreamException("Failed to write element", e);
        }
    }

    public void writeElement(String localName, String value) throws WikiStreamException
    {
        if (value != null) {
            writeStartElement(localName);
            writeCharacters(value);
            writeEndElement();
        }
    }

    public void writeCharacters(String text) throws WikiStreamException
    {
        try {
            this.writer.writeCharacters(text);
        } catch (XMLStreamException e) {
            throw new WikiStreamException("Failed to write element", e);
        }
    }

    public void writeStartElement(String localName) throws WikiStreamException
    {
        try {
            this.writer.writeStartElement(localName);
        } catch (XMLStreamException e) {
            throw new WikiStreamException("Failed to write element", e);
        }
    }

    public void writeEndElement() throws WikiStreamException
    {
        try {
            this.writer.writeEndElement();
        } catch (XMLStreamException e) {
            throw new WikiStreamException("Failed to write element", e);
        }
    }

    public void writeAttribute(String localName, String value) throws WikiStreamException
    {
        if (value != null) {
            try {
                this.writer.writeAttribute(localName, value);
            } catch (XMLStreamException e) {
                throw new WikiStreamException("Failed to write attribute", e);
            }
        }
    }

    /**
     * Close this writer and free any resources associated with the writer. This must not close the underlying output
     * stream.
     * 
     * @throws WikiStreamException
     */
    public void close() throws WikiStreamException
    {
        try {
            this.writer.close();
        } catch (XMLStreamException e) {
            throw new WikiStreamException("Failed to close writer", e);
        }
    }

    /**
     * Write any cached data to the underlying output mechanism.
     * 
     * @throws WikiStreamException
     */
    public void flush() throws WikiStreamException
    {
        try {
            this.writer.flush();
        } catch (XMLStreamException e) {
            throw new WikiStreamException("Failed to flush writer", e);
        }
    }
}
