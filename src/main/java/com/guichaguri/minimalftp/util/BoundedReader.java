package com.guichaguri.minimalftp.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;

public class BoundedReader extends BufferedReader {
    private static final int DEFAULT_MAX_LINE_LENGTH = 1024;    //Max bytes per line

    private int readerMaxLineLen;

    public BoundedReader(Reader reader, int maxLineLen) {
        super(reader);
        if (maxLineLen <= 0)
            throw new IllegalArgumentException("BoundedBufferedReader - maxLines and maxLineLen must be greater than 0");

        readerMaxLineLen = maxLineLen;
    }

    public BoundedReader(Reader reader) {
        super(reader);
        readerMaxLineLen = DEFAULT_MAX_LINE_LENGTH;
    }

    @Override
    public String readLine() throws IOException {
        //Check readerMaxLines limit
        int currentPos = 0;
        char[] data = new char[readerMaxLineLen];
        final int CR = 13;
        final int LF = 10;
        int currentChar = super.read();

        //Read characters and add them to the data buffer until we hit the end of a line or the end of the file.
        while ((currentChar != -1) && (currentChar != CR) && (currentChar != LF)) {
            data[currentPos++] = (char) currentChar;
            //Check readerMaxLineLen limit
            if (currentPos < readerMaxLineLen)
                currentChar = super.read();
            else
                throw new IllegalStateException("The line is too long");
        }

        if (currentChar == -1) {
            //End of file
            if (currentPos > 0)
                //Return last line
                return (new String(data, 0, currentPos));
            else
                return null;
        } else {
            //Remove newline characters from the buffer
            if (currentChar == CR) {
                //Check for LF and remove from buffer
                super.mark(1);
                if (super.read() != LF)
                    super.reset();
            }
            return (new String(data, 0, currentPos));
        }
    }
}
