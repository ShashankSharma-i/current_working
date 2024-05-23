package com.clientRackr.api.CTConstant;

public class CTConstant {


    public static final String RESEND_OTP_MAIL_SUBJECT = "Your New OTP Code";
    public static final String RESEND_OTP_MAIL_MESSAGE = "To complete your verification process, New OTP is : ";
    public static final String ACCOUNT_REGISTRATION_EMAIL_SUBJECT = "Verification Code for Account Registration";
    public static final String RESET_PASSWORD_OTP_EMAIL_SUBJECT = "Your Password Reset OTP";
    public static final String RESET_PASSWORD_OTP_EMAIL_MESSAGE = "Dear %s,\n\n" + "We received a request to reset your password. Please use the following One-Time Password (OTP) to reset your password:\n\n" + "OTP: %s\n\n" + "This OTP is valid for 10 minutes. If you did not request a password reset, please ignore this email or contact our support team immediately.\n\n" + "For your security, do not share this OTP with anyone.\n\n" + "Best regards,\n" + "Your Company Name\n" + "Support Team";
    public static final String OTP_MAIL_MESSAGE_FORMAT = "Your one-time password is ";
}
