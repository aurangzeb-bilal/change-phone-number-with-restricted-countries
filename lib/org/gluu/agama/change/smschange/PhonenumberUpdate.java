package org.gluu.agama.change.smschange;

import io.jans.agama.engine.service.FlowService;
import io.jans.as.common.model.common.User;
import io.jans.as.common.service.common.EncryptionService;
import io.jans.as.common.service.common.UserService;
import io.jans.orm.exception.operation.EntryNotFoundException;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.util.StringHelper;

import org.gluu.agama.change.users.UserphoneUpdate;
import io.jans.agama.engine.script.LogUtils;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import java.util.regex.Pattern;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jans.as.server.service.token.TokenService;
import io.jans.as.server.model.common.AuthorizationGrant;
import io.jans.as.server.model.common.AuthorizationGrantList;
import io.jans.as.server.model.common.AbstractToken;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

public class PhonenumberUpdate extends UserphoneUpdate {

    private static final Logger logger = LoggerFactory.getLogger(FlowService.class);

    private static final String MAIL = "mail";
    private static final String UID = "uid";
    private static final String DISPLAY_NAME = "displayName";
    private static final String GIVEN_NAME = "givenName";
    private static final String LAST_NAME = "sn";
    private static final String PASSWORD = "userPassword";
    private static final String INUM_ATTR = "inum";
    private static final int OTP_LENGTH = 6;
    private static final int OTP_CODE_LENGTH = 6;
    private static final String PHONE_VERIFIED = "phoneNumberVerified";
    private static final String PHONE_NUMBER = "mobile";
    private static final String EXT_ATTR = "jansExtUid";
    private static final String USER_STATUS = "jansStatus";
    private static final String EXT_UID_PREFIX = "github:";
    private static final String LANG = "lang";
    private Map<String, String> flowConfig;
    private static final SecureRandom RAND = new SecureRandom();

    private static final Map<String, String> otpStore = new HashMap<>();

    private static PhonenumberUpdate INSTANCE = null;

    public PhonenumberUpdate() {
    }

    public static synchronized PhonenumberUpdate getInstance(Map<String, String> config) {
        if (INSTANCE == null) {
            INSTANCE = new PhonenumberUpdate();
        }
        // Always update flowConfig to ensure latest config is used
        INSTANCE.flowConfig = config;
        return INSTANCE;
    }

    private UserService getUserService() {
        return CdiUtil.bean(UserService.class);
    }

    // validate token starts here
    public static Map<String, Object> validateBearerToken(String access_token) {
        Map<String, Object> result = new HashMap<>();

        try {
            if (access_token == null || access_token.trim().isEmpty()) {
                result.put("valid", false);
                result.put("errorMessage", "Access token is missing");
                return result;
            }

            // Get AuthorizationGrantList service
            AuthorizationGrantList authorizationGrantList = CdiUtil.bean(AuthorizationGrantList.class);
            if (authorizationGrantList == null) {
                result.put("valid", false);
                result.put("errorMessage", "Service not available");
                return result;
            }

            // Get the grant for this token
            AuthorizationGrant grant = authorizationGrantList.getAuthorizationGrantByAccessToken(access_token.trim());

            if (grant == null) {
                // Token not found
                result.put("valid", false);
                result.put("errorMessage", "Access token is invalid or expired");
                return result;
            }

            // Get the actual token object to check if it's valid (not expired)
            AbstractToken tokenObject = grant.getAccessToken(access_token.trim());

            // Check if token is active (exists and is valid)
            boolean isActive = tokenObject != null && tokenObject.isValid();

            if (isActive) {
                result.put("valid", true);
            } else {
                result.put("valid", false);
                result.put("errorMessage", "Access token is invalid or expired");
            }

        } catch (Exception e) {
            result.put("valid", false);
            result.put("errorMessage", "Access token is invalid or expired");
        }

        return result;
    }

    // validate token ends here

    public boolean passwordPolicyMatch(String userPassword) {
        String regex = '''^(?=.*[!@#$^&*])[A-Za-z0-9!@#$^&*]{6,}$''';
        Pattern pattern = Pattern.compile(regex);
        return pattern.matcher(userPassword).matches();
    }

    public boolean usernamePolicyMatch(String userName) {
        // Regex: Only alphabets (uppercase and lowercase), minimum 1 character
        String regex = '''^[A-Za-z]+$''';
        Pattern pattern = Pattern.compile(regex);
        return pattern.matcher(userName).matches();
    }

    public Map<String, String> getUserEntityByMail(String email) {
        User user = getUser(MAIL, email);
        boolean local = user != null;
        LogUtils.log("There is % local account for %", local ? "a" : "no", email);

        if (local) {
            String uid = getSingleValuedAttr(user, UID);
            String inum = getSingleValuedAttr(user, INUM_ATTR);
            String name = getSingleValuedAttr(user, GIVEN_NAME);

            if (name == null) {
                name = getSingleValuedAttr(user, DISPLAY_NAME);
                if (name == null && email != null && email.contains("@")) {
                    name = email.substring(0, email.indexOf("@"));
                }
            }

            // Creating a truly modifiable map
            Map<String, String> userMap = new HashMap<>();
            userMap.put(UID, uid);
            userMap.put(INUM_ATTR, inum);
            userMap.put("name", name);
            userMap.put("email", email);

            return userMap;
        }

        return new HashMap<>();
    }

    public Map<String, String> getUserEntityByUsername(String username) {
        User user = getUser(UID, username);
        boolean local = user != null;
        LogUtils.log("There is % local account for %", local ? "a" : "no", username);

        if (local) {
            String email = getSingleValuedAttr(user, MAIL);
            String inum = getSingleValuedAttr(user, INUM_ATTR);
            String name = getSingleValuedAttr(user, GIVEN_NAME);
            String uid = getSingleValuedAttr(user, UID); // Define uid properly
            String displayName = getSingleValuedAttr(user, DISPLAY_NAME);
            String givenName = getSingleValuedAttr(user, GIVEN_NAME);
            String sn = getSingleValuedAttr(user, LAST_NAME);
            String lang = getSingleValuedAttr(user, LANG);
            String phone = getSingleValuedAttr(user, PHONE_NUMBER);

            if (name == null) {
                name = getSingleValuedAttr(user, DISPLAY_NAME);
                if (name == null && email != null && email.contains("@")) {
                    name = email.substring(0, email.indexOf("@"));
                }
            }
            // Creating a modifiable HashMap directly
            Map<String, String> userMap = new HashMap<>();
            userMap.put(UID, uid);
            userMap.put(INUM_ATTR, inum);
            userMap.put("name", name);
            userMap.put("email", email);
            userMap.put(DISPLAY_NAME, displayName);
            userMap.put(LAST_NAME, sn);
            userMap.put(LANG, lang);
            userMap.put(PHONE_NUMBER, phone);

            return userMap;
        }

        return new HashMap<>();
    }

    public String updateUser(Map<String, String> profile) throws Exception {
        String inum = profile.get(INUM_ATTR);
        User user = getUser(INUM_ATTR, inum);

        if (user == null) {
            throw new EntryNotFoundException("User not found for inum: " + inum);
        }

        // 🔒 Preserve current email and lang
        String currentEmail = getSingleValuedAttr(user, MAIL);
        String currentLanguage = getSingleValuedAttr(user, LANG);

        // ✅ Update UID if provided
        String newUid = profile.get(UID);
        if (StringHelper.isNotEmpty(newUid)) {
            user.setAttribute(UID, newUid);
            user.setUserId(newUid);
        }

        // ✅ Always preserve email and lang
        if (StringHelper.isNotEmpty(currentEmail)) {
            user.setAttribute(MAIL, currentEmail);
        }
        if (StringHelper.isNotEmpty(currentLanguage)) {
            user.setAttribute(LANG, currentLanguage);
        }

        // ✅ Save the user
        UserService userService = CdiUtil.bean(UserService.class);
        user = userService.updateUser(user);

        if (user == null) {
            throw new EntryNotFoundException("Updated user not found");
        }

        return getSingleValuedAttr(user, INUM_ATTR);
    }

    public Map<String, String> getUserEntityByInum(String inum) {
        User user = getUser(INUM_ATTR, inum);
        boolean local = user != null;
        LogUtils.log("There is % local account for %", local ? "a" : "no", inum);

        if (local) {
            String email = getSingleValuedAttr(user, MAIL);
            // String inum = getSingleValuedAttr(user, INUM_ATTR);
            String name = getSingleValuedAttr(user, GIVEN_NAME);
            String uid = getSingleValuedAttr(user, UID); // Define uid properly
            String displayName = getSingleValuedAttr(user, DISPLAY_NAME);
            String givenName = getSingleValuedAttr(user, GIVEN_NAME);
            String sn = getSingleValuedAttr(user, LAST_NAME);
            String userPassword = getSingleValuedAttr(user, PASSWORD);
            String lang = getSingleValuedAttr(user, LANG);

            if (name == null) {
                name = getSingleValuedAttr(user, DISPLAY_NAME);
                if (name == null && email != null && email.contains("@")) {
                    name = email.substring(0, email.indexOf("@"));
                }
            }
            // Creating a modifiable HashMap directly
            Map<String, String> userMap = new HashMap<>();
            userMap.put(UID, uid);
            userMap.put("userId", uid);
            userMap.put(INUM_ATTR, inum);
            userMap.put("name", name);
            userMap.put("email", email);
            userMap.put(DISPLAY_NAME, displayName);
            userMap.put(LAST_NAME, sn);
            userMap.put(PASSWORD, userPassword);
            userMap.put(LANG, lang);

            return userMap;
        }

        return new HashMap<>();
    }

    private String getSingleValuedAttr(User user, String attribute) {
        Object value = null;
        if (attribute.equals(UID)) {
            // user.getAttribute("uid", true, false) always returns null :(
            value = user.getUserId();
        } else {
            value = user.getAttribute(attribute, true, false);
        }
        return value == null ? null : value.toString();

    }

    private User getUser(String attributeName, String value) {
        UserService userService = CdiUtil.bean(UserService.class);
        return userService.getUserByAttribute(attributeName, value, true);
    }

    public static Map<String, Object> syncUserWithExternal(String inum, Map<String, String> conf) {
        Map<String, Object> result = new HashMap<>();
        try {
            // Load config using CdiUtil or static ConfigService
            Map<String, String> config = new HashMap<>();
            if (conf == null) {
            result.put("status", "error");
            result.put("message", "Configuration is null");
            return result;
        }

            String publicKey = conf.get("PUBLIC_KEY");
            String privateKey = conf.get("PRIVATE_KEY");
            String apiBaseUrl = conf.get("API_BASE_URL");

            if (publicKey == null || privateKey == null) {
                result.put("status", "error");
                result.put("message", "PUBLIC_KEY or PRIVATE_KEY missing in config");
                return result;
            }
            
            // Use default API URL if not configured
            if (apiBaseUrl == null || apiBaseUrl.trim().isEmpty()) {
                apiBaseUrl = "https://api.phiwallet.dev";
            }

            // Generate HMAC-SHA256 signature (hex lowercase)
            String signature;
            try {
                javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
                javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(
                        privateKey.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        "HmacSHA256");
                mac.init(secretKey);
                byte[] hashBytes = mac.doFinal(inum.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                StringBuilder hex = new StringBuilder();
                for (byte b : hashBytes) {
                    String h = Integer.toHexString(0xff & b);
                    if (h.length() == 1)
                        hex.append('0');
                    hex.append(h);
                }
                signature = hex.toString().toLowerCase();
            } catch (Exception ex) {
                result.put("status", "error");
                result.put("message", "Failed to generate signature: " + ex.getMessage());
                return result;
            }

            // Build webhook URL
            String url = String.format("%s/v1/webhooks/users/%s/sync", apiBaseUrl, inum);

            // HTTP request
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("X-AUTH-CLIENT", publicKey)
                    .header("X-HMAC-SIGNATURE", signature)
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println(String.format("Webhook sync response status: %d, body: %s",
                    response.statusCode(), response.body()));

            if (response.statusCode() == 200) {
                result.put("status", "success");
            } else {
                result.put("status", "error");
                result.put("message", response.body());
            }

            return result;

        } catch (Exception e) {
            e.printStackTrace();
            result.put("status", "error");
            result.put("message", e.getMessage());
            return result;
        }
    }

    public boolean isPhoneVerified(String username) {
        try {
            User user = getUserService().getUser(username);
            if (user == null)
                return false;

            Object val = user.getAttribute("phoneNumberVerified", true, false);
            return val != null && Boolean.parseBoolean(val.toString());
        } catch (Exception e) {
            logger.error("Error checking phone verification for {}: {}", username, e.getMessage(), e);
            return false;
        }
    }

    public boolean isPhoneUnique(String username, String phone) {
        try {
            // Normalize phone number
            String normalizedPhone = phone.startsWith("+") ? phone : "+" + phone;

            // Check DB for existing users
            List<User> users = getUserService().getUsersByAttribute("mobile", normalizedPhone, true, 10);

            if (users != null && !users.isEmpty()) {
                for (User u : users) {
                    if (!u.getUserId().equalsIgnoreCase(username)) {
                        logger.info("Phone {} is NOT unique. Already used by {}", phone, u.getUserId());
                        return false; // duplicate
                    }
                }
            }

            logger.info("Phone {} is unique", phone);
            return true;
        } catch (Exception e) {
            logger.error("Error checking phone uniqueness for {}", phone, e);
            return false; // safest default on error
        }
    }

    public String getPhoneNumber(String username) {
        try {
            User user = getUserService().getUser(username);
            if (user == null)
                return null;
            Object phone = user.getAttribute(PHONE_NUMBER, true, false);
            return phone != null ? phone.toString() : null;
        } catch (Exception e) {
            logger.error("Error fetching phone number for {}: {}", username, e.getMessage(), e);
            return null;
        }
    }

    public String markPhoneAsVerified(String username, String phone) {
        try {
            User user = getUserService().getUser(username);
            if (user == null) {
                logger.warn("User {} not found while marking phone verified", username);
                return "User not found.";
            }

            // Set the phone number and mark it as verified
            user.setAttribute(PHONE_NUMBER, phone);
            user.setAttribute("phoneNumberVerified", Boolean.TRUE);
            getUserService().updateUser(user);

            logger.info("Phone {} verified and updated for user {}", phone, username);
            return "Phone " + phone + " verified successfully for user " + username;
        } catch (Exception e) {
            logger.error("Error marking phone verified for {}: {}", username, e.getMessage(), e);
            return "Error: " + e.getMessage();
        }
    }

    private String generateSMSOtpCode(int codeLength) {
        String numbers = "0123456789";
        SecureRandom random = new SecureRandom();
        char[] otp = new char[codeLength];
        for (int i = 0; i < codeLength; i++) {
            otp[i] = numbers.charAt(random.nextInt(numbers.length()));
        }
        return new String(otp);
    }

    public boolean sendOTPCode(String username, String phone) {
        try {
            // Get user preferred language from profile
            User user = getUserService().getUser(username);
            String lang = null;
            if (user != null) {
                Object val = user.getAttribute("lang", true, false);
                if (val != null) {
                    lang = val.toString().toLowerCase();
                }
            }
            if (lang == null || lang.isEmpty()) {
                lang = "en";
            }

            // Generate OTP
            String otpCode = generateSMSOtpCode(OTP_LENGTH);
            otpStore.put(phone, otpCode);
            logger.info("Generated OTP {} for phone {}", otpCode, phone);

            // Localized message
            Map<String, String> messages = new HashMap<>();

            messages.put("ar", "رمز التحقق OTP الخاص بك من Phi Wallet هو " + otpCode + ". لا تشاركه مع أي شخص.");
            messages.put("en", "Your Phi Wallet OTP is " + otpCode + ". Do not share it with anyone.");
            messages.put("es", "Tu código de Phi Wallet es " + otpCode + ". No lo compartas con nadie.");
            messages.put("fr", "Votre code Phi Wallet est " + otpCode + ". Ne le partagez avec personne.");
            messages.put("id", "Kode Phi Wallet Anda adalah " + otpCode + ". Jangan bagikan kepada siapa pun.");
            messages.put("pt", "O seu código da Phi Wallet é " + otpCode + ". Não o partilhe com ninguém.");

            String message = messages.getOrDefault(lang, messages.get("en"));

            // Determine which FROM_NUMBER to use based on country code
            String fromNumber = getFromNumberForPhone(phone);
            
            if (fromNumber == null || fromNumber.trim().isEmpty()) {
                logger.error("FROM_NUMBER is null or empty, cannot send OTP to {}", phone);
                return false;
            }

            // Send SMS
            PhoneNumber FROM_NUMBER = new PhoneNumber(fromNumber);
            PhoneNumber TO_NUMBER = new PhoneNumber(phone);

            Twilio.init(flowConfig.get("ACCOUNT_SID"), flowConfig.get("AUTH_TOKEN"));
            Message.creator(TO_NUMBER, FROM_NUMBER, message).create();

            logger.info("OTP sent to {} using sender {}", phone, fromNumber);
            return true;
        } catch (Exception ex) {
            logger.error("Failed to send OTP to {}. Error: {}", phone, ex.getMessage(), ex);
            return false;
        }
    }

    /**
     * Determines which FROM_NUMBER to use based on the phone number's country code.
     * Priority: 1) Countries in US_COUNTRY_CODES use FROM_NUMBER_US, 
     *          2) Countries in RESTRICTED_COUNTRY_CODES use FROM_NUMBER_RESTRICTED_COUNTRIES,
     *          3) All others use default FROM_NUMBER.
     */
    private String getFromNumberForPhone(String phone) {
        try {
            logger.info("=== getFromNumberForPhone START: phone='{}' ===", phone);
            String defaultFromNumber = flowConfig.get("FROM_NUMBER");
            String usCountryCodes = flowConfig.get("US_COUNTRY_CODES");
            String restrictedCodes = flowConfig.get("RESTRICTED_COUNTRY_CODES");
            
            if (defaultFromNumber == null || defaultFromNumber.trim().isEmpty()) {
                logger.error("FROM_NUMBER not configured");
                return null;
            }
            
            // Parse US country codes for matching
            Set<String> usCountrySet = new HashSet<>();
            if (usCountryCodes != null && !usCountryCodes.trim().isEmpty()) {
                usCountrySet = Arrays.stream(usCountryCodes.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet());
            }
            logger.info("US_COUNTRY_CODES from config: '{}' -> parsed to: {}", usCountryCodes, usCountrySet);
            
            // Parse restricted country codes for matching
            Set<String> restrictedSet = new HashSet<>();
            if (restrictedCodes != null && !restrictedCodes.trim().isEmpty()) {
                restrictedSet = Arrays.stream(restrictedCodes.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet());
            }
            
            // Combine both sets for accurate country code extraction
            Set<String> allKnownCodes = new HashSet<>();
            allKnownCodes.addAll(usCountrySet);
            allKnownCodes.addAll(restrictedSet);
            
            // Extract country code from phone number
            String countryCode = extractCountryCode(phone, allKnownCodes);
            logger.info("Phone: '{}' -> Extracted country code: '{}'", phone, countryCode);
            
            if (countryCode == null || countryCode.isEmpty()) {
                logger.info("No country code extracted, using default sender");
                return defaultFromNumber;
            }

            // Priority 1: Check if country code is in US_COUNTRY_CODES - use US-specific sender
            logger.info("Checking if country code '{}' is in US_COUNTRY_CODES: {}", countryCode, usCountrySet);
            logger.info("usCountrySet.size(): {}, usCountrySet.contains('{}'): {}", usCountrySet.size(), countryCode, usCountrySet.contains(countryCode));
            if (usCountrySet.contains(countryCode)) {
                String usFromNumber = flowConfig.get("FROM_NUMBER_US");
                logger.info("Retrieved FROM_NUMBER_US from config: '{}'", usFromNumber);
                
                if (usFromNumber != null && !usFromNumber.trim().isEmpty()) {
                    logger.info("Using US-specific sender {} for country code {}", usFromNumber, countryCode);
                    return usFromNumber;
                }
            }

            // Priority 2: Check if country code is in restricted list
            logger.info("Checking if country code '{}' is in restricted list: {}", countryCode, restrictedSet);
            if (restrictedSet.contains(countryCode)) {
                String restrictedFromNumber = flowConfig.get("FROM_NUMBER_RESTRICTED_COUNTRIES");
                
                if (restrictedFromNumber != null && !restrictedFromNumber.trim().isEmpty()) {
                    logger.info("Using restricted sender {} for country code {}", restrictedFromNumber, countryCode);
                    return restrictedFromNumber;
                }
            }

            logger.info("No matching category found, returning default sender: {}", defaultFromNumber);
            return defaultFromNumber;
        } catch (Exception ex) {
            logger.error("Error in getFromNumberForPhone: {}", ex.getMessage(), ex);
            return flowConfig.get("FROM_NUMBER");
        }
    }

    /**
     * Extract country code from phone number by matching against known codes.
     * Returns 1-digit code "1" or 2-3 digit country code.
     */
    private String extractCountryCode(String phone, Set<String> knownCodes) {
        logger.info("extractCountryCode: input phone='{}'", phone);
        
        if (phone == null || phone.trim().isEmpty()) {
            return null;
        }

        String cleaned = phone.startsWith("+") ? phone.substring(1) : phone;
        logger.info("extractCountryCode: after removing +, cleaned='{}'", cleaned);
        
        if (cleaned.length() < 2) {
            return null;
        }

        // Handle code "1" first (US/Canada and territories)
        boolean isDigit = cleaned.length() > 1 && Character.isDigit(cleaned.charAt(1));
        logger.info("extractCountryCode: startsWith('1')? {}, length > 1? {}, charAt(1) is digit? {}", 
                    cleaned.startsWith("1"), cleaned.length() > 1, isDigit);
        
        if (cleaned.startsWith("1") && cleaned.length() > 1 && Character.isDigit(cleaned.charAt(1))) {
            logger.info("extractCountryCode: returning '1'");
            return "1";
        }
        
        // Try 3-digit codes ONLY if they're in our knownCodes list
        if (cleaned.length() >= 3 && knownCodes != null && !knownCodes.isEmpty()) {
            String threeDigit = cleaned.substring(0, 3);
            if (knownCodes.contains(threeDigit)) {
                return threeDigit;
            }
        }
        
        // Default: Extract 2-digit country code
        return cleaned.substring(0, 2);
    }

    public boolean validateOTPCode(String phone, String code) {
        try {
            String storedCode = otpStore.getOrDefault(phone, "NULL");
            logger.info("User submitted code: {} — Stored code: {}", code, storedCode);
            if (storedCode.equalsIgnoreCase(code)) {
                otpStore.remove(phone); // remove after successful validation
                return true;
            }
            return false;
        } catch (Exception ex) {
            logger.error("Error validating OTP {} for phone {}: {}", code, phone, ex.getMessage(), ex);
            return false;
        }
    }

    public String getUserInumByUsername(String username) {
        User user = getUser(UID, username);
        boolean local = user != null;
        LogUtils.log("There is % local account for %", local ? "a" : "no", username);

        if (local) {
            String inum = getSingleValuedAttr(user, INUM_ATTR);
            return inum;
        }

        return null; // or return "" if you prefer
    }

}