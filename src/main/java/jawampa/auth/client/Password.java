package jawampa.auth.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import jawampa.WampMessages.AuthenticateMessage;
import jawampa.WampMessages.ChallengeMessage;

public class Password implements ClientSideAuthentication {
	public static final String AUTH_METHOD = "password";

	private final String ticket;

	public Password(String ticket) {
		this.ticket = ticket;
	}

	@Override
	public String getAuthMethod() {
		return AUTH_METHOD;
	}

	@Override
	public AuthenticateMessage handleChallenge(ChallengeMessage message,
			ObjectMapper objectMapper) {
		return new AuthenticateMessage(ticket, objectMapper.createObjectNode());
	}
}
