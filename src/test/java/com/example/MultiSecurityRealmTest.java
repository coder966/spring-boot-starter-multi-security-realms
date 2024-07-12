package com.example;

import com.example.dto.AuthOtpStepRequest;
import com.example.dto.AuthUsernameAndPasswordStepRequest;
import com.example.other.Constants;
import java.util.Objects;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpMethod;

@Slf4j
@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class MultiSecurityRealmTest {

    @LocalServerPort
    private int port;

    @Test
    public void testLoginWithUserFromDifferentRealm() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testLoginWithUserFromDifferentRealm");

        client
            .request(HttpMethod.POST, "/normal-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(LoginResponse.class)
            .expectStatus(401)
            .expectBody(new LoginResponse("NORMAL_USER", null, Constants.StepNames.USERNAME_AND_PASSWORD, Constants.ErrorCodes.BAD_CREDENTIALS));

        client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("mohammed", "mpass"))
            .exchange(LoginResponse.class)
            .expectStatus(401)
            .expectBody(new LoginResponse("ADMIN_USER", null, Constants.StepNames.USERNAME_AND_PASSWORD, Constants.ErrorCodes.BAD_CREDENTIALS));
    }

    @Test
    public void testAuthenticationFailure() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testAuthenticationFailure");

        LoginResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null))
            .readBody();

        client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("0000"))
            .exchange(LoginResponse.class)
            .expectStatus(401)
            .expectBody(new LoginResponse("ADMIN_USER", loginResponse.getToken(), Constants.StepNames.OTP, Constants.ErrorCodes.BAD_OTP));
    }

    @Test
    public void testAuthenticationSuccess() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testAuthenticationSuccess");

        LoginResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null))
            .readBody();

        client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", null, null));
    }

    @Test
    public void testAccessingProtectedApiFromAnotherRealm() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testAccessingProtectedApiFromAnotherRealm");

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .exchange(LoginResponse.class)
            .expectStatus(403);

        LoginResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null))
            .readBody();

        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", null, null))
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
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testAccessingOpenApis");

        client
            .request(HttpMethod.GET, "/my-third-open-api")
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("Normal User Open API");

        client
            .request(HttpMethod.GET, "/my-forth-open-api")
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("Normal User Open API");

        client
            .request(HttpMethod.GET, "/my-first-open-api")
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("Admin User Open API");

        client
            .request(HttpMethod.GET, "/my-second-open-api")
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("Admin User Open API");
    }

    @Test
    public void testAccessingProtectedApisWithAuthenticationNotFinishedAllSteps() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testAccessingProtectedApisWithAuthenticationNotFinishedAllSteps");

        client
            .request(HttpMethod.GET, "/admin-user/my-name")
            .exchange(LoginResponse.class)
            .expectStatus(403);

        LoginResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null))
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
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", null, null))
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

    @Test
    public void testTransactionalSupport() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "testTransactionalSupport");

        // Login to read the current counter

        LoginResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null))
            .readBody();

        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", null, null))
            .readBody();

        int loginCounter = client
            .request(HttpMethod.GET, "/admin-user/my-login-counter")
            .header("Authorization", loginResponse.getToken())
            .exchange(Integer.class)
            .expectStatus(200)
            .readBody();

        // now attempt a failed login, and then read the counter

        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null))
            .readBody();

        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("0000"))
            .exchange(LoginResponse.class)
            .expectStatus(401)
            .expectBody(new LoginResponse("ADMIN_USER", loginResponse.getToken(), Constants.StepNames.OTP, Constants.ErrorCodes.BAD_OTP))
            .readBody();

        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", null, null))
            .readBody();

        loginCounter = client
            .request(HttpMethod.GET, "/admin-user/my-login-counter")
            .header("Authorization", loginResponse.getToken())
            .exchange(Integer.class)
            .expectStatus(200)
            .expectBody(loginCounter + 1)
            .readBody();
    }

    @Test
    public void loginAgainAfterCompleteSuccessfulLogin() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "loginAgainAfterCompleteSuccessfulLogin");

        LoginResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null))
            .readBody();

        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", null, null))
            .readBody();

        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(LoginResponse.class)
            .expectStatus(400)
            .expectBody(new LoginResponse("ADMIN_USER", loginResponse.getToken(), null, "Already fully authenticated"))
            .readBody();
    }

    @Test
    public void authenticatedUserCanAccessPublicApi() {
        BrowserEmulatorTestHttpClient client = new BrowserEmulatorTestHttpClient(port, "authenticatedUserCanAccessPublicApi");

        // partially authenticated
        LoginResponse loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .body(new AuthUsernameAndPasswordStepRequest("khalid", "kpass"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", Constants.StepNames.OTP, null))
            .readBody();

        // public api from the same realm
        client
            .request(HttpMethod.GET, "/my-first-open-api")
            .header("Authorization", loginResponse.getToken())
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("Admin User Open API");

        // public api from the another realm
        client
            .request(HttpMethod.GET, "/my-forth-open-api")
            .header("Authorization", loginResponse.getToken())
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("Normal User Open API");

        // fully authenticated
        loginResponse = client
            .request(HttpMethod.POST, "/admin-user/auth")
            .header("Authorization", loginResponse.getToken())
            .body(new AuthOtpStepRequest("1234"))
            .exchange(LoginResponse.class)
            .expectStatus(200)
            .expectBody(new LoginResponse("ADMIN_USER", "ANY", null, null))
            .readBody();

        // public api from the same realm
        client
            .request(HttpMethod.GET, "/my-first-open-api")
            .header("Authorization", loginResponse.getToken())
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("Admin User Open API");

        // public api from the another realm
        client
            .request(HttpMethod.GET, "/my-forth-open-api")
            .header("Authorization", loginResponse.getToken())
            .exchange(String.class)
            .expectStatus(200)
            .expectBody("Normal User Open API");
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

            return Objects.equals(realm, otherResponse.getRealm()) &&
                Objects.equals(nextAuthenticationStep, otherResponse.getNextAuthenticationStep()) &&
                Objects.equals(error, otherResponse.getError()) &&
                (token == null ? otherResponse.getToken() == null : (token.equals("ANY") || Objects.equals(token, otherResponse.getToken())));
        }
    }

}