package net.coder966.spring.multisecurityrealms.other;

public class Constants {

    public interface Headers {

        String USERNAME = "X-Username";
        String PASSWORD = "X-Password";
        String OTP = "X-Otp";
    }

    public interface StepNames {

        String OTP = "OTP";
    }

    public interface ErrorCodes {

        String BAD_CREDENTIALS = "BAD_CREDENTIALS";
        String BAD_OTP = "BAD_OTP";
    }
}
