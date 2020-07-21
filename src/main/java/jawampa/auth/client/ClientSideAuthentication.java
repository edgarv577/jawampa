package jawampa.auth.client;

import jawampa.WampMessages.AuthenticateMessage;
import jawampa.WampMessages.ChallengeMessage;

import com.fasterxml.jackson.databind.ObjectMapper;

public interface ClientSideAuthentication {
    String getAuthMethod();
    AuthenticateMessage handleChallenge( ChallengeMessage message, ObjectMapper objectMapper );
}
