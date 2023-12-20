package net.coder966.spring.multisecurityrealms;

import net.coder966.spring.multisecurityrealms.other.Constants;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpMethod;

@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class MultiSecurityRealmTest {

    @LocalServerPort
    private int port;

    private final String NEXT_STEP_RESPONSE_HEADER_NAME = "X-Next-Auth-Step";
    private final String ERROR_CODE_RESPONSE_HEADER_NAME = "X-Auth-Error-Code";

    @Test
    public void testUserFromRealm2InRealm1() {
        SessionAwareTestHttpClient client = new SessionAwareTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/normal-user/login")
            .header(Constants.Headers.USERNAME, "khalid")
            .header(Constants.Headers.PASSWORD, "kpass")
            .exchange()
            .expectStatus(401)
            .expectHeaderDoesNotExist(NEXT_STEP_RESPONSE_HEADER_NAME);
    }

    @Test
    public void testUserFromRealm1InRealm2() {
        SessionAwareTestHttpClient client = new SessionAwareTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.USERNAME, "mohammed")
            .header(Constants.Headers.PASSWORD, "mpass")
            .exchange()
            .expectStatus(401)
            .expectHeaderDoesNotExist(NEXT_STEP_RESPONSE_HEADER_NAME)
            .expectHeader(ERROR_CODE_RESPONSE_HEADER_NAME, Constants.ErrorCodes.BAD_CREDENTIALS);
    }

    // -------------------------------------------------------------------------------------------------------------------------------------

    @Test
    public void testRealm1FirstStepFailure() {
        SessionAwareTestHttpClient client = new SessionAwareTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/normal-user/login")
            .header(Constants.Headers.USERNAME, "tester")
            .header(Constants.Headers.PASSWORD, "wrong")
            .exchange()
            .expectStatus(401)
            .expectHeaderDoesNotExist(NEXT_STEP_RESPONSE_HEADER_NAME)
            .expectHeader(ERROR_CODE_RESPONSE_HEADER_NAME, Constants.ErrorCodes.BAD_CREDENTIALS);
    }

    @Test
    public void testRealm1FirstStepSuccess() {
        SessionAwareTestHttpClient client = new SessionAwareTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/normal-user/login")
            .header(Constants.Headers.USERNAME, "mohammed")
            .header(Constants.Headers.PASSWORD, "mpass")
            .exchange()
            .expectStatus(200)
            .expectHeader(NEXT_STEP_RESPONSE_HEADER_NAME, Constants.StepNames.OTP)
            .expectHeaderDoesNotExist(ERROR_CODE_RESPONSE_HEADER_NAME);
    }

    @Test
    public void testRealm1SecondStepFailure() {
        SessionAwareTestHttpClient client = new SessionAwareTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/normal-user/login")
            .header(Constants.Headers.USERNAME, "mohammed")
            .header(Constants.Headers.PASSWORD, "mpass")
            .exchange()
            .expectStatus(200)
            .expectHeader(NEXT_STEP_RESPONSE_HEADER_NAME, Constants.StepNames.OTP)
            .expectHeaderDoesNotExist(ERROR_CODE_RESPONSE_HEADER_NAME);

        client
            .request(HttpMethod.POST, "/normal-user/login")
            .header(Constants.Headers.OTP, "0000")
            .exchange()
            .expectStatus(401)
            .expectHeaderDoesNotExist(NEXT_STEP_RESPONSE_HEADER_NAME)
            .expectHeader(ERROR_CODE_RESPONSE_HEADER_NAME, Constants.ErrorCodes.BAD_OTP);
    }

    @Test
    public void testRealm1SecondStepSuccess() {
        SessionAwareTestHttpClient client = new SessionAwareTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/normal-user/login")
            .header(Constants.Headers.USERNAME, "mohammed")
            .header(Constants.Headers.PASSWORD, "mpass")
            .exchange()
            .expectStatus(200)
            .expectHeader(NEXT_STEP_RESPONSE_HEADER_NAME, Constants.StepNames.OTP)
            .expectHeaderDoesNotExist(ERROR_CODE_RESPONSE_HEADER_NAME);

        client
            .request(HttpMethod.POST, "/normal-user/login")
            .header(Constants.Headers.OTP, "1234")
            .exchange()
            .expectStatus(200)
            .expectHeaderDoesNotExist(NEXT_STEP_RESPONSE_HEADER_NAME)
            .expectHeaderDoesNotExist(ERROR_CODE_RESPONSE_HEADER_NAME);
    }

    @Test
    public void testRealm1Logout() {
        SessionAwareTestHttpClient client = new SessionAwareTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/normal-user/logout")
            .exchange()
            .expectStatus(200);
    }

    // -------------------------------------------------------------------------------------------------------------------------------------

    @Test
    public void testRealm2FirstStepFailure() {
        SessionAwareTestHttpClient client = new SessionAwareTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.USERNAME, "tester")
            .header(Constants.Headers.PASSWORD, "wrong")
            .exchange()
            .expectStatus(401)
            .expectHeaderDoesNotExist(NEXT_STEP_RESPONSE_HEADER_NAME)
            .expectHeader(ERROR_CODE_RESPONSE_HEADER_NAME, Constants.ErrorCodes.BAD_CREDENTIALS);
    }

    @Test
    public void testRealm2FirstStepSuccess() {
        SessionAwareTestHttpClient client = new SessionAwareTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.USERNAME, "khalid")
            .header(Constants.Headers.PASSWORD, "kpass")
            .exchange()
            .expectStatus(200)
            .expectHeader(NEXT_STEP_RESPONSE_HEADER_NAME, Constants.StepNames.OTP)
            .expectHeaderDoesNotExist(ERROR_CODE_RESPONSE_HEADER_NAME);
    }

    @Test
    public void testRealm2SecondStepFailure() {
        SessionAwareTestHttpClient client = new SessionAwareTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.USERNAME, "khalid")
            .header(Constants.Headers.PASSWORD, "kpass")
            .exchange()
            .expectStatus(200)
            .expectHeader(NEXT_STEP_RESPONSE_HEADER_NAME, Constants.StepNames.OTP)
            .expectHeaderDoesNotExist(ERROR_CODE_RESPONSE_HEADER_NAME);

        client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.OTP, "0000")
            .exchange()
            .expectStatus(401)
            .expectHeaderDoesNotExist(NEXT_STEP_RESPONSE_HEADER_NAME)
            .expectHeader(ERROR_CODE_RESPONSE_HEADER_NAME, Constants.ErrorCodes.BAD_OTP);
    }

    @Test
    public void testRealm2SecondStepSuccess() {
        SessionAwareTestHttpClient client = new SessionAwareTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.USERNAME, "khalid")
            .header(Constants.Headers.PASSWORD, "kpass")
            .exchange()
            .expectStatus(200)
            .expectHeader(NEXT_STEP_RESPONSE_HEADER_NAME, Constants.StepNames.OTP)
            .expectHeaderDoesNotExist(ERROR_CODE_RESPONSE_HEADER_NAME);

        client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.OTP, "1234")
            .exchange()
            .expectStatus(200)
            .expectHeaderDoesNotExist(NEXT_STEP_RESPONSE_HEADER_NAME)
            .expectHeaderDoesNotExist(ERROR_CODE_RESPONSE_HEADER_NAME);
    }

    @Test
    public void testRealm2Logout() {
        SessionAwareTestHttpClient client = new SessionAwareTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/admin-user/logout")
            .exchange()
            .expectStatus(200);
    }
}