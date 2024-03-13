package net.coder966.spring.multisecurityrealms;

import net.coder966.spring.multisecurityrealms.other.Constants;
import net.coder966.spring.multisecurityrealms.utils.BrowserEmulatorTestHttpClient;
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
    public void testLoginWithUserFromDifferentRealm() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/normal-user/login")
            .header(Constants.Headers.USERNAME, "khalid")
            .header(Constants.Headers.PASSWORD, "kpass")
            .exchange()
            .expectStatus(401)
            .expectHeaderDoesNotExist(NEXT_STEP_RESPONSE_HEADER_NAME)
            .expectHeader(ERROR_CODE_RESPONSE_HEADER_NAME, Constants.ErrorCodes.BAD_CREDENTIALS);

        client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.USERNAME, "mohammed")
            .header(Constants.Headers.PASSWORD, "mpass")
            .exchange()
            .expectStatus(401)
            .expectHeaderDoesNotExist(NEXT_STEP_RESPONSE_HEADER_NAME)
            .expectHeader(ERROR_CODE_RESPONSE_HEADER_NAME, Constants.ErrorCodes.BAD_CREDENTIALS);
    }

    @Test
    public void testFirstStepBadCredentials() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

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
    public void testFirstStepCorrectCredentials() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

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
    public void testSecondStepBadCredentials() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

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
    public void testRealm2SecondCorrectCredentials() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

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
    public void testAccessingProtectedApiFromAnotherRealm() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .exchange(String.class)
            .expectStatus(403);

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

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("Khalid");

        client
            .request(HttpMethod.GET, "/normal-user/my-name")
            .exchange(String.class)
            .expectStatus(403);
    }

    @Test
    public void testAccessingOpenApis() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

        client
            .request(HttpMethod.GET, "/normal-user/my-first-open-api")
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("Normal User Open API");

        client
            .request(HttpMethod.GET, "/normal-user/my-second-open-api")
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("Normal User Open API");

        client
            .request(HttpMethod.GET, "/admin-user/my-first-open-api")
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("Admin User Open API");

        client
            .request(HttpMethod.GET, "/admin-user/my-second-open-api")
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("Admin User Open API");
    }

    @Test
    public void testLogout() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

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

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("Khalid");


        client
            .request(HttpMethod.POST, "/admin-user/logout")
            .exchange()
            .expectStatus(200);

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .exchange()
            .expectStatus(403);
    }
}