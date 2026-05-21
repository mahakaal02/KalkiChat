package ws

// RevocationEvent is a canonical session-revoked notification.
func RevocationEvent() ServerEvent {
	return ServerEvent{
		Type: "session.revoked",
		Data: map[string]any{"reason": "admin_action"},
	}
}

// KeyRotateEvent asks the device to upload a fresh signed prekey.
func KeyRotateEvent(epoch int) ServerEvent {
	return ServerEvent{
		Type: "key.rotate",
		Data: map[string]any{"epoch": epoch},
	}
}
