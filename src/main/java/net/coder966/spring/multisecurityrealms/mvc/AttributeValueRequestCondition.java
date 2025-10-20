package net.coder966.spring.multisecurityrealms.mvc;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.servlet.mvc.condition.RequestCondition;

public class AttributeValueRequestCondition implements RequestCondition<AttributeValueRequestCondition> {

    private final String attributeName;
    private final Object expectedValue;

    public AttributeValueRequestCondition(String attributeName, Object expectedValue) {
        this.attributeName = attributeName;
        this.expectedValue = expectedValue;
    }

    @Override
    public AttributeValueRequestCondition getMatchingCondition(HttpServletRequest request) {
        Object actualValue = request.getAttribute(attributeName);
        if (expectedValue == null) {
            return actualValue == null ? this : null;
        }
        return expectedValue.equals(actualValue) ? this : null;
    }

    @Override
    public AttributeValueRequestCondition combine(AttributeValueRequestCondition other) {
        return other;
    }

    @Override
    public int compareTo(AttributeValueRequestCondition other, HttpServletRequest request) {
        return 0;
    }

    @Override
    public String toString() {
        return "AttributeValueRequestCondition[" + attributeName + "=" + expectedValue + "]";
    }
}
