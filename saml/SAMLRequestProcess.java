/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package saml;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Base64;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 *
 * @author DPatra
 */
public class SAMLRequestProcess extends HttpServlet {

    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code> methods.
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        try {
             String SAMLRequest = request.getParameter("SAMLRequest");
             //String relayStateURL = request.getParameter("RelayState");
             //String requestXmlString = decodeAuthnRequestXML(SAMLRequest);
             System.out.println(SAMLRequest);
             com.fm.fmwebcare.util.UtilSAML.readAuthnAssertion(SAMLRequest,request,response);

       } catch (Exception ex) {
                Logger.getLogger(SAMLRequestProcess.class.getName()).log(Level.SEVERE, null, ex);
                     Logger.getLogger(SAMLRequestProcess.class.getName()).log(Level.SEVERE, null, ex);

        } finally {
            out.close();
        }
    }

    static String decodeAuthnRequestXML(String encodedRequestXmlString)
      throws Exception {
    try {
      // URL decode
      // No need to URL decode: auto decoded by request.getParameter() method

      // Base64 decode
      Base64 base64Decoder = new Base64();
      byte[] xmlBytes = encodedRequestXmlString.getBytes("UTF-8");
      byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);

      //Uncompress the AuthnRequest data
      //First attempt to unzip the byte array according to DEFLATE (rfc 1951)
      try {

        Inflater inflater = new Inflater(true);
        inflater.setInput(base64DecodedByteArray);
        // since we are decompressing, it's impossible to know how much space we
        // might need; hopefully this number is suitably big
        byte[] xmlMessageBytes = new byte[5000];
        int resultLength = inflater.inflate(xmlMessageBytes);

        if (!inflater.finished()) {
          throw new RuntimeException("didn't allocate enough space to hold "
            + "decompressed data");
        }

        inflater.end();
        return new String(xmlMessageBytes, 0, resultLength, "UTF-8");

      } catch (DataFormatException e) {

        // if DEFLATE fails, then attempt to unzip the byte array according to
        // zlib (rfc 1950)
        ByteArrayInputStream bais = new ByteArrayInputStream(
          base64DecodedByteArray);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        InflaterInputStream iis = new InflaterInputStream(bais);
        byte[] buf = new byte[1024];
        int count = iis.read(buf);
        while (count != -1) {
          baos.write(buf, 0, count);
          count = iis.read(buf);
        }
        iis.close();
        return new String(baos.toByteArray());
      }

    } catch (UnsupportedEncodingException e) {
      throw new Exception("Error decoding AuthnRequest: " +
            "Check decoding scheme - " + e.getMessage());
    } catch (IOException e) {
      throw new Exception("Error decoding AuthnRequest: " +
            "Check decoding scheme - " + e.getMessage());
    }
  }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}