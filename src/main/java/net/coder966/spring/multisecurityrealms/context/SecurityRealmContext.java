package net.coder966.spring.multisecurityrealms.context;

import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmDescriptor;

public class SecurityRealmContext {

    private static final ThreadLocal<SecurityRealmDescriptor> descriptor = new ThreadLocal<>();
    private static final ThreadLocal<String> currentStep = new ThreadLocal<>();

    public static void setDescriptor(SecurityRealmDescriptor descriptor) {
        SecurityRealmContext.descriptor.set(descriptor);
    }

    public static SecurityRealmDescriptor getDescriptor() {
        return SecurityRealmContext.descriptor.get();
    }

    public static void setCurrentStep(String step) {
        SecurityRealmContext.currentStep.set(step);
    }

    public static String getCurrentStep() {
        return SecurityRealmContext.currentStep.get();
    }
}
