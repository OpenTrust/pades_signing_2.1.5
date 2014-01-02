package com.opentrust.spi.pdf;

import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.X509Principal;

import com.opentrust.spi.crypto.CertificateHelper;
import com.opentrust.spi.helpers.DateHelper;
import com.opentrust.spi.helpers.StringHelper;
import com.opentrust.spi.logger.Channel;
import com.opentrust.spi.logger.SPILogger;

public class PDFSignaturesHelper {
    private final static SPILogger logger = SPILogger.getLogger("PDFSIGN");

    // BEGIN HELPER METHODS
//    static File getTempPDFFile() {
//        try {
//            File localRoot = getTempPDFFolder();
//            File tempFile = File.createTempFile("tmp_spipdf_", ".pdf", localRoot);
//            return tempFile;
//        } catch(Exception e) {
//            ExceptionHandler.handleNoThrow(e,"Could not create tmp pdf file");
//        }
//        return null;
//    }
//    static File getTempPDFFolder() {
//        try {
//            String localRootPath = Config.getConfig().getStringProperty(CommonProperties.COM_LOCAL_TMPDIR);
//            File localRoot = new File(localRootPath+File.separatorChar+"pdf");
//            if (localRoot.exists())
//                FileHelper.canUseDirectory(localRoot.getAbsolutePath(),
//                        "rw");
//            else
//                localRoot.mkdirs();
//            return localRoot;
//        } catch(Exception e) {
//            ExceptionHandler.handleNoThrow(e,"Could not create tmp pdf folder");
//        }
//        return null;
//    }

    public static String buildSignatureAppearanceDescription(String descriptionTemplate,
            X509Certificate signerCertificate,
            Calendar signingTime,
            String location, String reason, String contact) throws SPIIllegalArgumentException {
        
        String result = descriptionTemplate;
        
        // First deal with potential variable replacements in description
        if (descriptionTemplate != null && descriptionTemplate.contains("$")) {
            logger.debug(Channel.TECH, "Building PDF appearance description, template is %1$s",
                descriptionTemplate);
            // Variable syntax is: $variable_name or $variable_name[custom_param1;custom_param2;...]
            Map<String,String> tokens = new HashMap<String,String>();
            // List of supported variable names in description
            final String VARNAME_SIGNER_DN = "signer_dn";
            final String VARNAME_SIGNER_NAME = "signer_name";
            final String VARNAME_SIGNING_TIME = "signing_time";
            final String VARNAME_LOCATION = "location";
            final String VARNAME_REASON = "reason";
            final String VARNAME_CONTACT = "contact";
            // Fill variable values to be used for replacement
            if(signingTime!=null) {
                String signingTimeStr = DateHelper.toSimpleLongString(signingTime.getTime());
                tokens.put(VARNAME_SIGNING_TIME, signingTimeStr);
            }
            else {
                tokens.put(VARNAME_SIGNING_TIME, null); // so that when signing_time variable is used without signing time provided, an exception is thrown 
            }
            if(signerCertificate!=null) {
                X500Principal signer = signerCertificate.getSubjectX500Principal();
                String signerName = signer.getName();
                tokens.put(VARNAME_SIGNER_DN, signerName);
                tokens.put(VARNAME_SIGNER_NAME, getCNOrDefaultForPrincipal(signer));
            } else {
                tokens.put(VARNAME_SIGNER_DN,null); // so that when signer_dn variable is used without input certificate, an exception is thrown 
                tokens.put(VARNAME_SIGNER_NAME, null); // so that when signer_name variable is used without input certificate, an exception is thrown
            }
            tokens.put(VARNAME_LOCATION, location);
            tokens.put(VARNAME_REASON, reason);
            tokens.put(VARNAME_CONTACT, contact);

            //Iterate over variables found in description to perform replacement
            Pattern variablePattern = Pattern.compile("\\$("+StringHelper.join(tokens.keySet().iterator(), "|")
                    +")(\\[([^\\]]*)\\])?");
            Matcher variableMatcher = variablePattern.matcher(descriptionTemplate);
            StringBuffer sb = new StringBuffer();
            while(variableMatcher.find()) {
                String variableName = variableMatcher.group(1);
                String replacement = tokens.get(variableName);
                String variableOptionalParams = variableMatcher.group(3);
                if (variableOptionalParams != null) {
                    if (VARNAME_SIGNING_TIME.equals(variableName) && signingTime != null ) {
                        // Use custom-formatted signing_time instead of toSimpleLongString signing_time
                        try {
                            String[] params = variableOptionalParams.split(";");
                            String customDateFormat = params[0];
                            String customTimezone = params.length > 1 ? params[1].trim() : null;
                            String customLocale = params.length > 2 ? params[2].trim() : null;
                            SimpleDateFormat dateFormat = customLocale != null ?
                                    new SimpleDateFormat(customDateFormat, new Locale(customLocale)) : new SimpleDateFormat(customDateFormat);
                                    if (customTimezone != null)
                                        dateFormat.setTimeZone(TimeZone.getTimeZone(customTimezone.trim()));
                                    replacement = dateFormat.format(signingTime.getTime());
                        } catch(Throwable e) {
                            throw new SPIIllegalArgumentException(e,
                                    "Could not recognize valid signing time date format '%1$s' in description parameter: %2$s",
                                    variableOptionalParams, e.toString());
                        }
                    }
                }
                if(replacement==null) {
                    if (VARNAME_SIGNER_DN.equals(variableName) || VARNAME_SIGNER_NAME.equals(variableName))
                        throw new SPIIllegalArgumentException("Attempt to use certificate-related variable in signature description without providing the signer certificate");
                    else if (VARNAME_SIGNING_TIME.equals(variableName))
                        throw new SPIIllegalArgumentException("Attempt to use signing time variable in signature description without provided signing time value");
                    else
                        throw new SPIIllegalArgumentException("Attempt to use %1$s variable in signature description without providing the corresponding value",
                                variableName);
                }
                else {
                    //We need to escape $ character in replacement string, otherwise appendReplacement will fail
                    replacement  = replacement.replaceAll("\\$", "\\\\\\$");
                }
                variableMatcher.appendReplacement(sb, replacement);
            }
            variableMatcher.appendTail(sb);
            result = sb.toString();
            logger.debug(Channel.TECH, "Final PDF appearance description value is %1$s", result);
        }
        else {
            logger.debug(Channel.TECH, "Building PDF appearance description, no variable replacement needed in appearance description");
        }
        
        return result;
    }

    // copied from admin-web, ACBean class. TODO : put this in a helper package
    private static String getCNOrDefaultForPrincipal(X500Principal principal) {
        String name = null;
        try {
            name = CertificateHelper.getCNFromDN(principal.getName());
        } catch (IllegalArgumentException e) {}
        if(name == null || name.length() == 0) {
            try {
                X509Principal  p=new X509Principal(principal.getEncoded());
                name = (String)p.getValues().lastElement();
            } catch(Exception e) {
                name = "";
            }
        }
        return name;
    }
    // END HELPER METHODS
}
