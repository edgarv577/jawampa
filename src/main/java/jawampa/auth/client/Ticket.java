package jawampa.auth.client;

import jawampa.WampMessages.AuthenticateMessage;
import jawampa.WampMessages.ChallengeMessage;

import com.fasterxml.jackson.databind.ObjectMapper;

public class Ticket implements ClientSideAuthentication {
	public static final String AUTH_METHOD = "ticket";
	
	private final String ticket;
	
	public Ticket(String ticket) {
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
