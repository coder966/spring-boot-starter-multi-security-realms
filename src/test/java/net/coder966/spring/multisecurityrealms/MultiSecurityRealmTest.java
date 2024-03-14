package net.coder966.spring.multisecurityrealms;

import java.util.Objects;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import net.coder966.spring.multisecurityrealms.converter.BrowserEmulatorTestHttpClient;
import net.coder966.spring.multisecurityrealms.other.Constants;
import net.coder966.spring.multisecurityrealms.other.Constants.ErrorCodes;
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

    @Test
    public void testLoginWithUserFromDifferentRealm() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/normal-user/login")
            .header(Constants.Headers.USERNAME, "khalid")
            .header(Constants.Headers.PASSWORD, "kpass")
            .exchange(LoginResponse.class)
            .expectStatus(401)
            .expectBody(new LoginResponse("NORMAL_USER", null, null, Constants.ErrorCodes.BAD_CREDENTIALS));

        client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.USERNAME, "mohammed")
            .header(Constants.Headers.PASSWORD, "mpass")
            .exchange(LoginResponse.class)
            .expectStatus(401)
            .expectBody(new LoginResponse("ADMIN_USER", null, null, Constants.ErrorCodes.BAD_CREDENTIALS));
    }

    @Test
    public void testFirstStepBadCredentials() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.USERNAME, "tester")
            .header(Constants.Headers.PASSWORD, "wrong")
            .exchange(LoginResponse.class)
            .expectStatus(401)
            .expectBody(new LoginResponse("ADMIN_USER", null, null, Constants.ErrorCodes.BAD_CREDENTIALS));
    }

    @Test
    public void testFirstStepCorrectCredentials() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

        client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.USERNAME, "khalid")
            .header(Constants.Headers.PASSWORD, "kpass")
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "any not null", Constants.StepNames.OTP, null));
    }

    @Test
    public void testSecondStepBadCredentials() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

        LoginResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.USERNAME, "khalid")
            .header(Constants.Headers.PASSWORD, "kpass")
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "any not null", Constants.StepNames.OTP, null))
            .readBody();

        client
            .request(HttpMethod.POST, "/admin-user/login")
            .header("Authorization", loginResponse.getToken())
            .header(Constants.Headers.OTP, "0000")
            .exchange(LoginResponse.class)
            .expectStatus(401)
            .expectBody(new LoginResponse("ADMIN_USER", null, null, ErrorCodes.BAD_OTP));
    }

    @Test
    public void testRealm2SecondCorrectCredentials() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

        LoginResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.USERNAME, "khalid")
            .header(Constants.Headers.PASSWORD, "kpass")
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "any not null", Constants.StepNames.OTP, null))
            .readBody();

        client
            .request(HttpMethod.POST, "/admin-user/login")
            .header("Authorization", loginResponse.getToken())
            .header(Constants.Headers.OTP, "1234")
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "any not null", null, null));
    }

    @Test
    public void testAccessingProtectedApiFromAnotherRealm() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .exchange(LoginResponse.class)
            .expectStatus(403);

        LoginResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.USERNAME, "khalid")
            .header(Constants.Headers.PASSWORD, "kpass")
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "any not null", Constants.StepNames.OTP, null))
            .readBody();

        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/login")
            .header("Authorization", loginResponse.getToken())
            .header(Constants.Headers.OTP, "1234")
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "any not null", null, null))
            .readBody();

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .header("Authorization", loginResponse.getToken())
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("khalid");

        client
            .request(HttpMethod.GET, "/normal-user/my-name")
            .header("Authorization", loginResponse.getToken())
            .exchange(LoginResponse.class)
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
    public void testAccessingProtectedApisWithAuthenticationNotFinishedAllSteps() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port);

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .exchange(LoginResponse.class)
            .expectStatus(403);

        LoginResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/login")
            .header(Constants.Headers.USERNAME, "khalid")
            .header(Constants.Headers.PASSWORD, "kpass")
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "any not null", Constants.StepNames.OTP, null))
            .readBody();

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .header("Authorization", loginResponse.getToken())
            .exchange(LoginResponse.class)
            .expectStatus(403);

        client
            .request(HttpMethod.GET, "/admin-user/no-pre-authorize")
            .header("Authorization", loginResponse.getToken())
            .exchange()
            .expectStatus(403);

        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/login")
            .header("Authorization", loginResponse.getToken())
            .header(Constants.Headers.OTP, "1234")
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "any not null", null, null))
            .readBody();

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .header("Authorization", loginResponse.getToken())
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("khalid");

        client
            .request(HttpMethod.GET, "/admin-user/no-pre-authorize")
            .header("Authorization", loginResponse.getToken())
            .exchange(String.class)
            .expectStatus(200);
    }

    @Setter
    @Getter
    @ToString
    @AllArgsConstructor
    public static class LoginResponse {
        private String realm;
        private String token;
        private String nextAuthenticationStep;
        private String error;

        @Override
        public boolean equals(Object other) {
            if(!(other instanceof LoginResponse otherResponse)){
                return false;
            }

            return Objects.equals(otherResponse.getRealm(), realm) &&
                Objects.equals(otherResponse.getNextAuthenticationStep(), nextAuthenticationStep) &&
                Objects.equals(otherResponse.getError(), error) &&
                (otherResponse.getToken() == null ? token == null : true);
        }
    }

}